/**
 * BPC replica receiver — the inverse of ReplicatingPairStore.
 *
 * Ingests replicated ReplicaOps into the replica node's local PairStore. This
 * is the VPS-side half of HA replication. Framework-agnostic: the demo/prod
 * HTTP server calls handleReplicaIngest(), which authenticates the complete
 * envelope before applying a strictly ordered mutation.
 *
 * Design:
 *  RX-01 Authenticated envelope:
 *    The x-replica-signature header authenticates the source, sequence,
 *    timestamp, and complete operation body with HMAC-SHA-256.
 *
 *  RX-02 Ordered, idempotent application:
 *    The receiver accepts only the next sequence for a source and recognizes
 *    an exact retry of the most recently accepted envelope. Stale or gapped
 *    mutations are rejected before touching the store.
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
import type { PairStore } from './store.js';
import type { ReplicaOp } from './replicating-store.js';
import type { StoredPair, PairRegistration } from './types.js';
import {
  validateReplicaEnvelope,
  verifyReplicaEnvelopeSignature,
  replicaOperationDigest,
  type ReplicaApplyGuard,
  type ReplicaEnvelope,
} from './replica-envelope.js';

const MAX_PAIR_ID_LEN = 64;
const MAX_TOKEN_LEN = 256;
const VALID_SCOPES = new Set(['read', 'read-write', 'admin']);
const VALID_MODES = new Set(['development', 'production']);
const VALID_STATUSES = new Set(['active', 'locked', 'expired', 'rotated', 'revoked']);
const VALID_PAIR_KINDS = new Set(['legitimate', 'ghost']);
const VALID_CANARY_CLASSES = new Set(['env_file', 'docs', 'registry_exfil']);

export interface ReplicaApplyResult {
  ok: boolean;
  error?: string;
}

/** Verify the HMAC that authenticates and integrity-protects a replica envelope. */
export function authorizeReplica(
  headers: Record<string, string | string[] | undefined>,
  envelope: ReplicaEnvelope,
  expectedKey: string,
): boolean {
  const raw = headers['x-replica-signature'];
  if (Array.isArray(raw)) return false;
  return verifyReplicaEnvelopeSignature(envelope, raw, expectedKey);
}

function isValidPairId(id: unknown): id is string {
  return typeof id === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(id);
}

function isValidJwk(jwk: unknown): jwk is JsonWebKey {
  if (!jwk || typeof jwk !== 'object' || Array.isArray(jwk)) return false;
  const value = jwk as Record<string, unknown>;
  return value['kty'] === 'EC' && value['crv'] === 'P-256' &&
    typeof value['x'] === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value['x']) &&
    typeof value['y'] === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value['y']);
}

function isValidRegistration(value: unknown): value is PairRegistration {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const registration = value as Partial<PairRegistration>;
  return typeof registration.name === 'string' && registration.name.length >= 1 && registration.name.length <= 128 &&
    VALID_SCOPES.has(registration.scope as string) && VALID_MODES.has(registration.mode as string) &&
    typeof registration.secretHash === 'string' && /^[A-Za-z0-9_-]{43}$/.test(registration.secretHash) &&
    isValidJwk(registration.pubJwk);
}

function isValidStoredPair(value: unknown): value is StoredPair {
  if (!isValidRegistration(value)) return false;
  const pair = value as StoredPair;
  const kind = pair.kind ?? 'legitimate';
  const canaryIsValid = kind === 'ghost'
    ? VALID_CANARY_CLASSES.has(pair.canaryClass as string)
    : pair.canaryClass === undefined;
  return isValidPairId(pair.id) && VALID_STATUSES.has(pair.status) &&
    Number.isSafeInteger(pair.created) && pair.created >= 0 &&
    (pair.lastActive === null || (Number.isSafeInteger(pair.lastActive) && pair.lastActive >= 0)) &&
    Number.isSafeInteger(pair.requests) && pair.requests >= 0 &&
    Number.isSafeInteger(pair.failedSigs) && pair.failedSigs >= 0 &&
    (pair.cumulativeFailures === undefined ||
      (Number.isFinite(pair.cumulativeFailures) && pair.cumulativeFailures >= 0)) &&
    (pair.firstFailureAt === undefined || pair.firstFailureAt === null ||
      (Number.isSafeInteger(pair.firstFailureAt) && pair.firstFailureAt >= 0)) &&
    (pair.expiresAt === undefined || (Number.isSafeInteger(pair.expiresAt) && pair.expiresAt >= 0)) &&
    (pair.maxRequests === undefined || (Number.isSafeInteger(pair.maxRequests) && pair.maxRequests >= 0)) &&
    VALID_PAIR_KINDS.has(kind) && canaryIsValid;
}

/** Validate the op envelope shape before touching the store (RX-04). */
export function validateReplicaOp(body: unknown): { ok: true; op: ReplicaOp } | { ok: false; error: string } {
  if (!body || typeof body !== 'object') return { ok: false, error: 'invalid_body' };
  const op = (body as { op?: unknown }).op;
  switch (op) {
    case 'set': {
      const pair = (body as { pair?: unknown }).pair as StoredPair | undefined;
      if (!isValidStoredPair(pair)) {
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
      if (!isValidRegistration(registration)) {
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
  expectedKey: string,
  expectedSourceId: string,
  applyGuard: ReplicaApplyGuard,
  nowMs = Date.now(),
): Promise<{ status: number; result: ReplicaApplyResult }> {
  const envelopeResult = validateReplicaEnvelope(body, expectedSourceId, nowMs);
  if (!envelopeResult.ok) {
    return { status: 400, result: { ok: false, error: envelopeResult.error } };
  }
  const envelope = envelopeResult.envelope;
  if (!authorizeReplica(headers, envelope, expectedKey)) {
    return { status: 401, result: { ok: false, error: 'unauthorized' } };
  }
  const validated = validateReplicaOp(envelope.op);
  if (!validated.ok) {
    return { status: 400, result: { ok: false, error: validated.error } };
  }
  let applyResult: ReplicaApplyResult = { ok: false, error: 'apply_failed' };
  const disposition = await applyGuard.applyIfNext(
    envelope.sourceId,
    envelope.sequence,
    replicaOperationDigest(validated.op),
    async () => {
      applyResult = await applyReplicaOp(store, validated.op);
      return applyResult.ok;
    },
  );
  if (disposition === 'applied') return { status: 200, result: { ok: true } };
  if (disposition === 'duplicate') return { status: 200, result: { ok: true, error: 'duplicate_ignored' } };
  if (disposition === 'apply_failed') return { status: 500, result: applyResult };
  return { status: 409, result: { ok: false, error: `replica_sequence_${disposition}` } };
}
