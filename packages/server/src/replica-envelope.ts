import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

import type { ReplicaOp } from './replicating-store.js';

export const REPLICA_ENVELOPE_VERSION = 'bpc.replica.v1' as const;
export const DEFAULT_REPLICA_FRESHNESS_MS = 60_000;

export interface ReplicaEnvelope {
  version: typeof REPLICA_ENVELOPE_VERSION;
  sourceId: string;
  sequence: number;
  sentAt: number;
  op: ReplicaOp;
}

export interface ReplicaSequenceSource {
  /** Return the next durable, strictly increasing sequence for this source. */
  next(): Promise<number>;
}

/** Development/test sequence source. Production HA must persist this value. */
export class MemoryReplicaSequenceSource implements ReplicaSequenceSource {
  private sequence: number;

  constructor(initialSequence = 0) {
    if (!Number.isSafeInteger(initialSequence) || initialSequence < 0) {
      throw new TypeError('initialSequence must be a non-negative safe integer');
    }
    this.sequence = initialSequence;
  }

  async next(): Promise<number> {
    this.sequence += 1;
    return this.sequence;
  }
}

export type ReplicaApplyDisposition =
  | 'applied'
  | 'duplicate'
  | 'conflict'
  | 'stale'
  | 'gap'
  | 'apply_failed';

export interface ReplicaApplyGuard {
  /**
   * Atomically check source ordering, apply the mutation, and commit the new
   * sequence. A production implementation must persist the committed sequence
   * in the same transaction as the replica mutation.
   */
  applyIfNext(
    sourceId: string,
    sequence: number,
    operationDigest: string,
    apply: () => Promise<boolean>,
  ): Promise<ReplicaApplyDisposition>;
}

/** Process-local serialized guard for tests and single-process development. */
export class MemoryReplicaApplyGuard implements ReplicaApplyGuard {
  private readonly lastBySource = new Map<string, { sequence: number; operationDigest: string }>();
  private tail: Promise<void> = Promise.resolve();

  async applyIfNext(
    sourceId: string,
    sequence: number,
    operationDigest: string,
    apply: () => Promise<boolean>,
  ): Promise<ReplicaApplyDisposition> {
    let resolveResult!: (value: ReplicaApplyDisposition) => void;
    const result = new Promise<ReplicaApplyDisposition>((resolve) => { resolveResult = resolve; });

    this.tail = this.tail.then(async () => {
      const state = this.lastBySource.get(sourceId);
      const last = state?.sequence ?? 0;
      if (sequence === last) {
        resolveResult(state?.operationDigest === operationDigest ? 'duplicate' : 'conflict');
        return;
      }
      if (sequence < last) { resolveResult('stale'); return; }
      if (sequence !== last + 1) { resolveResult('gap'); return; }
      if (!await apply()) { resolveResult('apply_failed'); return; }
      this.lastBySource.set(sourceId, { sequence, operationDigest });
      resolveResult('applied');
    }).catch(() => resolveResult('apply_failed'));

    return result;
  }

  lastSequence(sourceId: string): number {
    return this.lastBySource.get(sourceId)?.sequence ?? 0;
  }
}

/** Stable digest used to distinguish an exact retry from a sequence conflict. */
export function replicaOperationDigest(op: ReplicaOp): string {
  return createHash('sha256').update(canonicalJson(op), 'utf8').digest('hex');
}

export function signReplicaEnvelope(envelope: ReplicaEnvelope, key: string): string {
  assertReplicaKey(key);
  return createHmac('sha256', key).update(canonicalReplicaEnvelope(envelope), 'utf8').digest('hex');
}

export function verifyReplicaEnvelopeSignature(
  envelope: ReplicaEnvelope,
  presentedSignature: unknown,
  key: string,
): boolean {
  if (typeof presentedSignature !== 'string' || !/^[0-9a-f]{64}$/i.test(presentedSignature)) return false;
  let expected: string;
  try {
    expected = signReplicaEnvelope(envelope, key);
  } catch {
    return false;
  }
  const a = Buffer.from(presentedSignature, 'hex');
  const b = Buffer.from(expected, 'hex');
  return a.length === b.length && timingSafeEqual(a, b);
}

export function validateReplicaEnvelope(
  body: unknown,
  expectedSourceId: string,
  nowMs = Date.now(),
  freshnessMs = DEFAULT_REPLICA_FRESHNESS_MS,
): { ok: true; envelope: ReplicaEnvelope } | { ok: false; error: string } {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return { ok: false, error: 'invalid_envelope' };
  const envelope = body as Partial<ReplicaEnvelope>;
  if (envelope.version !== REPLICA_ENVELOPE_VERSION) return { ok: false, error: 'invalid_envelope_version' };
  if (envelope.sourceId !== expectedSourceId || !isSafeIdentifier(envelope.sourceId)) {
    return { ok: false, error: 'invalid_replica_source' };
  }
  if (!Number.isSafeInteger(envelope.sequence) || (envelope.sequence ?? 0) < 1) {
    return { ok: false, error: 'invalid_replica_sequence' };
  }
  if (typeof envelope.sentAt !== 'number' || !Number.isFinite(envelope.sentAt)) {
    return { ok: false, error: 'invalid_replica_timestamp' };
  }
  if (Math.abs(nowMs - envelope.sentAt) > freshnessMs) return { ok: false, error: 'replica_request_expired' };
  if (!envelope.op || typeof envelope.op !== 'object') return { ok: false, error: 'invalid_replica_op' };
  if (canonicalJson(envelope).length > 65_536) return { ok: false, error: 'replica_envelope_too_large' };
  return { ok: true, envelope: envelope as ReplicaEnvelope };
}

export function canonicalReplicaEnvelope(envelope: ReplicaEnvelope): string {
  return canonicalJson({
    op: envelope.op,
    sentAt: envelope.sentAt,
    sequence: envelope.sequence,
    sourceId: envelope.sourceId,
    version: envelope.version,
  });
}

function assertReplicaKey(key: string): void {
  if (typeof key !== 'string' || Buffer.byteLength(key, 'utf8') < 32) {
    throw new TypeError('replication authentication key must contain at least 32 bytes');
  }
}

function isSafeIdentifier(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z0-9_.:-]{1,128}$/.test(value);
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = sortValue((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return value;
}
