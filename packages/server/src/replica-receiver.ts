/**
 * BPC replica receiver — the inverse of ReplicatingPairStore.
 *
 * Ingests replicated ReplicaOps into the replica node's local PairStore. This
 * is the VPS-side half of HA replication. Framework-agnostic: the demo/prod
 * HTTP server calls authorizeReplica() then applyReplicaOp().
 *
 * Design:
 *  RX-01 Constant-time token auth:
 *    The x-replica-token header is compared in constant time to defeat timing
 *    oracles. A mismatch is rejected before any store mutation.
 *
 *  RX-02 Idempotent application:
 *    Replication is at-least-once — the decorator retries pushes, so an op that
 *    succeeded server-side but timed out client-side WILL be re-sent. Every op
 *    here is idempotent: set/delete are absolute; setPending/deletePending are
 *    absolute. Re-applying any op leaves the replica in the same state.
 *
 *  RX-03 Verifier-only by nature (BPC is asymmetric):
 *    A replicated StoredPair carries secretHash (verifier) + pubJwk (public).
 *    The replica can fully validate BPC requests on failover with NO secret
 *    exposure — this is the BPC advantage over TSK's shared-secret model.
 *
 *  RX-04 Strict op validation:
 *    Malformed/oversized/unknown ops are rejected, never partially applied.
 *
 * NIST SP 800-53 Rev 5: AU-9, SC-8, SI-10 (information input validation).
 */
import { timingSafeEqual } from 'node:crypto';
import type { PairStore } from './store.js';
import type { ReplicaOp } from './replicating-store.js';
import type { StoredPair, PairRegistration } from './types.js';

const MAX_PAIR_ID_LEN = 64;
const MAX_TOKEN_LEN = 256;

export interface ReplicaApplyResult {
  ok: boolean;
  error?: string;
}

/** Constant-time comparison of the presented replica token against the expected one. */
export function authorizeReplica(
  headers: Record<string, string | string[] | undefined>,
  expectedToken: string,
): boolean {
  const raw = headers['x-replica-token'];
  const presented = Array.isArray(raw) ? raw[0] : raw;
  if (!presented || typeof presented !== 'string') return false;
  if (presented.length > MAX_TOKEN_LEN || expectedToken.length > MAX_TOKEN_LEN) return false;
  const a = Buffer.from(presented);
  const b = Buffer.from(expectedToken);
  // timingSafeEqual requires equal length; length itself is not a secret here,
  // but we still avoid an early-return branch on the secret bytes.
  if (a.length !== b.length) {
    // Compare against self to keep timing roughly constant, then fail.
    timingSafeEqual(a, a);
    return false;
  }
  return timingSafeEqual(a, b);
}

function isValidPairId(id: unknown): id is string {
  return typeof id === 'string' && id.length > 0 && id.length <= MAX_PAIR_ID_LEN;
}

/** Validate the op envelope shape before touching the store (RX-04). */
export function validateReplicaOp(body: unknown): { ok: true; op: ReplicaOp } | { ok: false; error: string } {
  if (!body || typeof body !== 'object') return { ok: false, error: 'invalid_body' };
  const op = (body as { op?: unknown }).op;
  switch (op) {
    case 'set': {
      const pair = (body as { pair?: unknown }).pair as StoredPair | undefined;
      if (!pair || typeof pair !== 'object' || !isValidPairId((pair as StoredPair).id)) {
        return { ok: false, error: 'invalid_set' };
      }
      return { ok: true, op: { op: 'set', pair } };
    }
    case 'delete': {
      const pairId = (body as { pairId?: unknown }).pairId;
      if (!isValidPairId(pairId)) return { ok: false, error: 'invalid_delete' };
      return { ok: true, op: { op: 'delete', pairId } };
    }
    case 'setPending': {
      const { token, registration, requestedAt } = body as {
        token?: unknown; registration?: unknown; requestedAt?: unknown;
      };
      if (typeof token !== 'string' || token.length === 0 || token.length > MAX_TOKEN_LEN) {
        return { ok: false, error: 'invalid_pending_token' };
      }
      if (!registration || typeof registration !== 'object') {
        return { ok: false, error: 'invalid_pending_registration' };
      }
      if (typeof requestedAt !== 'number' || !Number.isFinite(requestedAt)) {
        return { ok: false, error: 'invalid_pending_requestedAt' };
      }
      return { ok: true, op: { op: 'setPending', token, registration: registration as PairRegistration, requestedAt } };
    }
    case 'deletePending': {
      const token = (body as { token?: unknown }).token;
      if (typeof token !== 'string' || token.length === 0 || token.length > MAX_TOKEN_LEN) {
        return { ok: false, error: 'invalid_pending_token' };
      }
      return { ok: true, op: { op: 'deletePending', token } };
    }
    default:
      return { ok: false, error: 'unknown_op' };
  }
}

/** Apply a validated op to the replica store. Idempotent (RX-02). */
export async function applyReplicaOp(store: PairStore, op: ReplicaOp): Promise<ReplicaApplyResult> {
  try {
    switch (op.op) {
      case 'set':           await store.set(op.pair); return { ok: true };
      case 'delete':        await store.delete(op.pairId); return { ok: true };
      case 'setPending':    await store.setPending(op.token, op.registration, op.requestedAt); return { ok: true };
      case 'deletePending': await store.deletePending(op.token); return { ok: true };
      default:              return { ok: false, error: 'unknown_op' };
    }
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : 'apply_failed' };
  }
}

/**
 * One-call convenience: authorize + validate + apply. Returns an HTTP-ish
 * status so the transport layer can map it directly.
 */
export async function handleReplicaIngest(
  store: PairStore,
  headers: Record<string, string | string[] | undefined>,
  body: unknown,
  expectedToken: string,
): Promise<{ status: number; result: ReplicaApplyResult }> {
  if (!authorizeReplica(headers, expectedToken)) {
    return { status: 401, result: { ok: false, error: 'unauthorized' } };
  }
  const validated = validateReplicaOp(body);
  if (!validated.ok) {
    return { status: 400, result: { ok: false, error: validated.error } };
  }
  const result = await applyReplicaOp(store, validated.op);
  return { status: result.ok ? 200 : 500, result };
}
