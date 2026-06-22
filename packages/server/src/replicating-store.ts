/**
 * ReplicatingPairStore — async write-mirroring decorator for HA BPC.
 *
 * Wraps ANY primary PairStore and mirrors every mutation to a remote replica
 * over HTTPS. Design principles (resilient-identity hardening):
 *
 *  HA-01 Local-first authority:
 *    The primary write completes and is returned to the caller BEFORE the
 *    replica is touched. A replica that is slow, down, or unreachable NEVER
 *    blocks or fails a primary write. Availability of the primary is
 *    independent of the replica — the Windows node keeps serving if the VPS
 *    replica is offline.
 *
 *  HA-02 Bounded retry queue (no memory exhaustion):
 *    Failed pushes are retried with exponential backoff. The queue is capped
 *    (MAX_QUEUE) and sheds OLDEST entries when full — a long replica outage
 *    cannot exhaust primary memory. Shed events are surfaced via onDrop so the
 *    operator sees replication lag instead of a silent gap.
 *
 *  HA-03 Replicate verifiers only, never secrets:
 *    A StoredPair contains secretHash (an HKDF-derived verifier) and pubJwk
 *    (public key) — never a private key or raw secret. Mirroring the full pair
 *    to the replica is therefore safe: a compromised replica cannot forge a
 *    session binding because it holds no signing material.
 *
 *  HA-04 Fail-closed lives elsewhere:
 *    This decorator is about availability of the principal store. Authorization
 *    fail-closed semantics (expired/tampered cache → deny) live in the client
 *    cache + middleware layers, NOT here. This store never weakens auth.
 *
 * NIST SP 800-53 Rev 5: CP-9 (system backup), CP-10 (recovery), SC-5 (DoS
 * protection via bounded queue), AU-9 (protection of audit information).
 */
import type { PairStore } from './store.js';
import type { StoredPair, PairRegistration } from './types.js';

export type ReplicaOp =
  | { op: 'set'; pair: StoredPair }
  | { op: 'delete'; pairId: string }
  | { op: 'setPending'; token: string; registration: PairRegistration; requestedAt: number }
  | { op: 'deletePending'; token: string };

export interface ReplicaTarget {
  /** Base URL of the replica ingest endpoint, e.g. https://srv1740069.hstgr.cloud/replica */
  url: string;
  /** Shared replication auth token (sent as x-replica-token). NOT a BPC secret. */
  token: string;
  /** Per-request timeout. Default 5000ms. */
  timeoutMs?: number;
}

export interface ReplicatingStoreOptions {
  /** Max queued ops before oldest are shed. Default 5000. */
  maxQueue?: number;
  /** Base backoff in ms for retries. Default 1000. */
  backoffBaseMs?: number;
  /** Max backoff in ms. Default 30_000. */
  backoffMaxMs?: number;
  /** Called when an op is shed because the queue is full (replication lag alarm). */
  onDrop?: (op: ReplicaOp, queueDepth: number) => void;
  /** Called on each push outcome — wire to metrics/health. */
  onPush?: (ok: boolean, op: ReplicaOp, attempt: number) => void;
  /** Injectable fetch for tests. Defaults to global fetch. */
  fetchImpl?: typeof fetch;
}

const DEFAULTS = {
  maxQueue: 5000,
  backoffBaseMs: 1000,
  backoffMaxMs: 30_000,
  timeoutMs: 5000,
};

export class ReplicatingPairStore implements PairStore {
  private readonly queue: ReplicaOp[] = [];
  private draining = false;
  private attempt = 0;
  private readonly opts: Required<Omit<ReplicatingStoreOptions, 'onDrop' | 'onPush' | 'fetchImpl'>> &
    Pick<ReplicatingStoreOptions, 'onDrop' | 'onPush' | 'fetchImpl'>;

  constructor(
    private readonly primary: PairStore,
    private readonly replica: ReplicaTarget,
    options: ReplicatingStoreOptions = {},
  ) {
    this.opts = {
      maxQueue: options.maxQueue ?? DEFAULTS.maxQueue,
      backoffBaseMs: options.backoffBaseMs ?? DEFAULTS.backoffBaseMs,
      backoffMaxMs: options.backoffMaxMs ?? DEFAULTS.backoffMaxMs,
      onDrop: options.onDrop,
      onPush: options.onPush,
      fetchImpl: options.fetchImpl,
    };
  }

  // ── Reads always hit the authoritative primary ──────────────────────────────
  get(pairId: string) { return this.primary.get(pairId); }
  list() { return this.primary.list(); }
  getPending(token: string) { return this.primary.getPending(token); }
  listPending() { return this.primary.listPending(); }

  // ── Writes: primary first (authoritative), then async mirror ────────────────
  async set(pair: StoredPair): Promise<void> {
    await this.primary.set(pair);
    this.enqueue({ op: 'set', pair });
  }

  async delete(pairId: string): Promise<void> {
    await this.primary.delete(pairId);
    this.enqueue({ op: 'delete', pairId });
  }

  async setPending(token: string, registration: PairRegistration, requestedAt: number): Promise<void> {
    await this.primary.setPending(token, registration, requestedAt);
    this.enqueue({ op: 'setPending', token, registration, requestedAt });
  }

  async deletePending(token: string): Promise<void> {
    await this.primary.deletePending(token);
    this.enqueue({ op: 'deletePending', token });
  }

  // ── Replication queue ───────────────────────────────────────────────────────

  /** Current number of unreplicated ops — wire to a "replication lag" gauge. */
  get queueDepth(): number { return this.queue.length; }

  private enqueue(op: ReplicaOp): void {
    // HA-02: shed OLDEST when full so a long outage can't exhaust memory.
    if (this.queue.length >= this.opts.maxQueue) {
      const dropped = this.queue.shift();
      if (dropped) this.opts.onDrop?.(dropped, this.queue.length);
    }
    this.queue.push(op);
    void this.drain();
  }

  /** Drains the queue with exponential backoff. Single concurrent drainer. */
  private async drain(): Promise<void> {
    if (this.draining) return;
    this.draining = true;
    try {
      while (this.queue.length > 0) {
        const op = this.queue[0];
        const ok = await this.push(op);
        if (ok) {
          this.queue.shift();
          this.attempt = 0;
        } else {
          // Leave op at head, back off, then loop retries it.
          this.attempt++;
          await this.sleep(this.backoff());
        }
      }
    } finally {
      this.draining = false;
    }
  }

  private backoff(): number {
    const ms = this.opts.backoffBaseMs * 2 ** Math.min(this.attempt, 10);
    return Math.min(ms, this.opts.backoffMaxMs);
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((r) => setTimeout(r, ms));
  }

  private async push(op: ReplicaOp): Promise<boolean> {
    const doFetch = this.opts.fetchImpl ?? fetch;
    try {
      const res = await doFetch(`${this.replica.url}/pair`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-replica-token': this.replica.token,
        },
        body: JSON.stringify({ ...op, ts: Date.now() }),
        signal: AbortSignal.timeout(this.replica.timeoutMs ?? DEFAULTS.timeoutMs),
      });
      const ok = res.ok;
      this.opts.onPush?.(ok, op, this.attempt);
      return ok;
    } catch {
      this.opts.onPush?.(false, op, this.attempt);
      return false;
    }
  }

  /** Test/operational hook: wait until the queue is fully replicated or timeout. */
  async flush(timeoutMs = 10_000): Promise<boolean> {
    const start = Date.now();
    while (this.queue.length > 0) {
      if (Date.now() - start > timeoutMs) return false;
      await this.sleep(25);
    }
    return true;
  }
}
