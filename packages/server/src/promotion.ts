/**
 * Promotion gate — Option A split-brain protection (guard-gated single writer).
 *
 * The fleet guard is the SOLE authority for write routing. A replica node never
 * self-promotes and a client never promotes it; only the guard, via the admin
 * command endpoint, may flip a replica between read-only and writable.
 *
 *  PR-01 Single writer invariant:
 *    A primary is always writable. A replica is writable ONLY while the guard
 *    has explicitly promoted it. assertWritable() returns 503 otherwise, so even
 *    a buggy client that routes a write to a non-promoted replica FAILS CLOSED —
 *    the replica can never accept an authoritative write it wasn't promoted for.
 *
 *  PR-02 Explicit demotion (no fail-back race):
 *    promoted does NOT auto-clear. When the primary recovers, the guard must
 *    explicitly demote() the replica before traffic fails back. This removes the
 *    window where a recovering primary and a still-writable replica both accept
 *    writes. Demotion is a deliberate guard action, never automatic.
 *
 *  PR-03 Guard-only control via constant-time admin auth:
 *    promote/demote commands require the guard token (x-guard-token), compared
 *    in constant time. Replication ingest (the primary mirroring to the replica)
 *    is a SEPARATE path and is unaffected — the replica keeps syncing while
 *    read-only, which is exactly what makes a later promotion safe.
 *
 * NIST SP 800-53 Rev 5: AC-3 (access enforcement), CP-10, SC-7, AU-2.
 */
import { timingSafeEqual } from 'node:crypto';

export type NodeRole = 'primary' | 'replica';

export interface PromotionSnapshot {
  role: NodeRole;
  writable: boolean;
  promoted: boolean;
  promotedAt: number | null;
  promotedBy: string | null;
  reason: string | null;
}

const MAX_TOKEN_LEN = 256;

export class PromotionController {
  private promoted = false;
  private promotedAt: number | null = null;
  private promotedBy: string | null = null;
  private reason: string | null = null;

  constructor(public readonly role: NodeRole) {}

  /** Guard-only: promote a replica to accept client writes. Throws on a primary. */
  promote(by: string, reason = ''): PromotionSnapshot {
    if (this.role !== 'replica') {
      throw new Error('promote: only a replica node can be promoted');
    }
    this.promoted = true;
    this.promotedAt = Date.now();
    this.promotedBy = by;
    this.reason = reason;
    return this.snapshot();
  }

  /** Guard-only: demote a replica back to read-only (PR-02: required before fail-back). */
  demote(by: string, reason = ''): PromotionSnapshot {
    if (this.role !== 'replica') {
      throw new Error('demote: only a replica node can be demoted');
    }
    this.promoted = false;
    this.promotedAt = null;
    this.promotedBy = by;
    this.reason = reason;
    return this.snapshot();
  }

  /** A primary is always writable; a replica only while promoted. */
  isWritable(): boolean {
    return this.role === 'primary' || this.promoted;
  }

  snapshot(): PromotionSnapshot {
    return {
      role: this.role,
      writable: this.isWritable(),
      promoted: this.promoted,
      promotedAt: this.promotedAt,
      promotedBy: this.promotedBy,
      reason: this.reason,
    };
  }
}

/**
 * Gate for client-facing MUTATING endpoints (register/rotate/revoke/provision).
 * Returns 503 'replica_not_promoted' on a non-promoted replica (PR-01 fail-closed).
 * Does NOT gate replication ingest — that path stays open so the replica stays synced.
 */
export function assertWritable(
  ctrl: PromotionController,
): { ok: true } | { ok: false; status: number; error: string } {
  if (ctrl.isWritable()) return { ok: true };
  return { ok: false, status: 503, error: 'replica_not_promoted' };
}

function constantTimeTokenMatch(presented: unknown, expected: string): boolean {
  if (typeof presented !== 'string' || !presented) return false;
  if (presented.length > MAX_TOKEN_LEN || expected.length > MAX_TOKEN_LEN) return false;
  const a = Buffer.from(presented);
  const b = Buffer.from(expected);
  if (a.length !== b.length) {
    timingSafeEqual(a, a);
    return false;
  }
  return timingSafeEqual(a, b);
}

export interface PromotionCommand {
  command: 'promote' | 'demote';
  by: string;
  reason?: string;
}

/**
 * Admin command endpoint (guard-only). Authenticates the guard token in constant
 * time, then promotes/demotes. Returns an HTTP-ish status for the transport.
 */
export function handlePromotionCommand(
  ctrl: PromotionController,
  headers: Record<string, string | string[] | undefined>,
  body: unknown,
  guardToken: string,
): { status: number; result: unknown } {
  const raw = headers['x-guard-token'];
  const presented = Array.isArray(raw) ? raw[0] : raw;
  if (!constantTimeTokenMatch(presented, guardToken)) {
    return { status: 401, result: { ok: false, error: 'unauthorized' } };
  }
  if (!body || typeof body !== 'object') {
    return { status: 400, result: { ok: false, error: 'invalid_body' } };
  }
  const { command, by, reason } = body as Partial<PromotionCommand>;
  if (command !== 'promote' && command !== 'demote') {
    return { status: 400, result: { ok: false, error: 'invalid_command' } };
  }
  if (typeof by !== 'string' || by.length === 0) {
    return { status: 400, result: { ok: false, error: 'missing_by' } };
  }
  try {
    const snap = command === 'promote' ? ctrl.promote(by, reason ?? '') : ctrl.demote(by, reason ?? '');
    return { status: 200, result: { ok: true, snapshot: snap } };
  } catch (e) {
    return { status: 409, result: { ok: false, error: e instanceof Error ? e.message : 'command_failed' } };
  }
}
