/**
 * BPC Key Rotation Handler
 *
 * Security hardening:
 *
 *  BPC-02 FIX — Rotation DoS (ReferenceError: payload is not defined):
 *    `payload` is declared in the outer scope so it is accessible after the
 *    try/catch block. (Previously try-scoped → ReferenceError crashed the
 *    process on every valid rotation.)
 *
 *  ROT-01 FIX — Both-pairs-active window (atomicity):
 *    The old pair is marked 'rotated' BEFORE the new pair is created, so a
 *    crash mid-rotation fails CLOSED (old key disabled) rather than leaving two
 *    simultaneously-valid keys. If new-pair persistence fails, the old pair
 *    stays disabled and an error is returned for operator re-rotation.
 *
 *  ROT-02 FIX — Order-sensitive JWK binding:
 *    new_pub_jwk binding uses a field-wise comparison of cryptographic key
 *    material (sameJwk) instead of JSON.stringify equality, which was sensitive
 *    to key ordering and could false-reject legitimate rotations.
 *
 *  ROT-03 FIX — Audit emission:
 *    Rotation now emits chained audit events (rotate + register on success,
 *    verify_fail on bad signature) so the most security-sensitive operation is
 *    no longer invisible in the hash-chained audit trail.
 *
 *  ROT-04 — Public key structural validation (reject malformed/unsupported keys).
 *
 *  NIST SP 800-53 Rev 5 controls: IA-3, SC-8, SI-10, SI-11, AU-2.
 */

import { importPublicKeyFromJwk, verifyPayload, generateId } from '@bpc/core';
import type { PairStore } from './store.js';
import type { StoredPair } from './types.js';
import type { AuditLog } from './audit.js';

export interface RotationRequest {
  oldPairId: string;
  newPubJwk: JsonWebKey;
  /** ECDSA signature over canonicalized rotation payload */
  signature: string;
  /** Canonicalized payload JSON string, base64url-encoded */
  signedData: string;
  timestamp: number;
}

export interface RotationResult {
  ok: boolean;
  newPairId?: string;
  error?: string;
}

/** Maximum input size limits to prevent oversized-payload DoS. */
const MAX_PAIR_ID_LEN     = 64;
const MAX_SIGNED_DATA_LEN = 4096;
const MAX_SIGNATURE_LEN   = 200;

/** Structural validation of a PUBLIC JWK. Rejects malformed/unsupported keys. */
function isValidPublicJwk(jwk: unknown): jwk is JsonWebKey {
  if (!jwk || typeof jwk !== 'object') return false;
  const k = jwk as Record<string, unknown>;
  if (typeof k['kty'] !== 'string') return false;
  switch (k['kty']) {
    case 'EC':
      return typeof k['crv'] === 'string' && typeof k['x'] === 'string' && typeof k['y'] === 'string';
    case 'OKP':
      return typeof k['crv'] === 'string' && typeof k['x'] === 'string';
    case 'RSA':
      return typeof k['n'] === 'string' && typeof k['e'] === 'string';
    default:
      return false;
  }
}

/**
 * Compare the cryptographic material of two public JWKs, order-independent.
 * Only key-defining fields are compared (private fields must never be present
 * in a rotation request and are ignored).
 */
function sameJwk(a: JsonWebKey, b: JsonWebKey): boolean {
  const fields: (keyof JsonWebKey)[] = ['kty', 'crv', 'x', 'y', 'n', 'e'];
  return fields.every(f => a[f] === b[f]);
}

/**
 * Rotate a pair: verify the OLD key signs the rotation request, disable the old
 * pair (fail-closed), then create the new pair. Emits chained audit events.
 */
export async function handleRotation(
  req: RotationRequest,
  store: PairStore,
  sigWindowMs = 60_000,
  auditLog?: AuditLog,
): Promise<RotationResult> {
  const fail = async (error: string, pairId?: string): Promise<RotationResult> => {
    if (error === 'invalid_signature') {
      await auditLog?.write({ action: 'verify_fail', pairId: pairId ?? req.oldPairId, error });
    }
    return { ok: false, error };
  };

  // ── Input validation ─────────────────────────────────────────────────────
  if (!req.oldPairId || typeof req.oldPairId !== 'string' || req.oldPairId.length > MAX_PAIR_ID_LEN) {
    return fail('invalid_request');
  }
  if (!req.signedData || typeof req.signedData !== 'string' || req.signedData.length > MAX_SIGNED_DATA_LEN) {
    return fail('invalid_request');
  }
  if (!req.signature || typeof req.signature !== 'string' || req.signature.length > MAX_SIGNATURE_LEN) {
    return fail('invalid_request');
  }
  if (typeof req.timestamp !== 'number' || !Number.isFinite(req.timestamp)) {
    return fail('invalid_request');
  }
  // ROT-04: structural key validation (was: only typeof object).
  if (!isValidPublicJwk(req.newPubJwk)) {
    return fail('invalid_request');
  }

  // 1. Timestamp freshness (reject both stale and far-future within the window).
  if (Math.abs(Date.now() - req.timestamp) > sigWindowMs) {
    return fail('timestamp_expired');
  }

  // 2. Lookup old pair
  const oldPair = await store.get(req.oldPairId);
  if (!oldPair) return fail('unknown_pair');
  if (oldPair.status !== 'active') return fail('pair_not_active');

  // 3. Decode + parse signed rotation payload (BPC-02: payload in outer scope).
  let payload: Record<string, unknown>;
  try {
    const padded = req.signedData.replace(/-/g, '+').replace(/_/g, '/');
    const padLen  = (4 - padded.length % 4) % 4;
    const json    = atob(padded + '='.repeat(padLen));
    payload = JSON.parse(json) as Record<string, unknown>;
  } catch {
    return fail('invalid_signed_data');
  }

  // 4. Verify ECDSA signature with the OLD key.
  let valid = false;
  try {
    const pubKey = await importPublicKeyFromJwk(oldPair.pubJwk);
    valid = await verifyPayload(pubKey, payload, req.signature);
  } catch {
    valid = false;
  }
  if (!valid) return fail('invalid_signature');

  // 5. Bind rotation payload to request parameters.
  if (payload['purpose']     !== 'rotation')    return fail('payload_field_mismatch');
  if (payload['old_pair_id'] !== req.oldPairId) return fail('payload_field_mismatch');
  if (payload['timestamp']   !== req.timestamp) return fail('payload_field_mismatch');

  const newPubJwkJson = payload['new_pub_jwk_json'];
  if (typeof newPubJwkJson !== 'string') return fail('payload_field_mismatch');
  let parsedNewPubJwk: JsonWebKey;
  try {
    parsedNewPubJwk = JSON.parse(newPubJwkJson) as JsonWebKey;
  } catch {
    return fail('invalid_signed_data');
  }
  if (!isValidPublicJwk(parsedNewPubJwk)) return fail('invalid_request');
  // ROT-02: order-independent cryptographic-material comparison.
  if (!sameJwk(parsedNewPubJwk, req.newPubJwk)) return fail('payload_field_mismatch');

  // 6. ROT-01: disable old pair FIRST (fail-closed), then create the new pair.
  oldPair.status = 'rotated';
  await store.set(oldPair);

  const newPairId = generateId('pair');
  const newPair: StoredPair = {
    id:         newPairId,
    name:       oldPair.name,
    scope:      oldPair.scope,
    mode:       oldPair.mode,
    secretHash: oldPair.secretHash,
    pubJwk:     req.newPubJwk,
    status:     'active',
    created:    Date.now(),
    lastActive: null,
    requests:   0,
    failedSigs: 0,
    expiresAt:  oldPair.expiresAt,
  };
  try {
    await store.set(newPair);
  } catch (err) {
    await auditLog?.write({
      action: 'rotate', severity: 'CRITICAL', pairId: req.oldPairId,
      error: 'new_pair_persist_failed',
      detail: JSON.stringify({ attemptedNewPairId: newPairId }),
    });
    return { ok: false, error: 'rotation_persist_failed' };
  }

  // 7. ROT-03: emit chained audit events for the rotation + new registration.
  await auditLog?.write({
    action: 'rotate', pairId: req.oldPairId,
    detail: JSON.stringify({ newPairId }),
  });
  await auditLog?.write({
    action: 'register', pairId: newPairId,
    detail: JSON.stringify({ rotatedFrom: req.oldPairId }),
  });

  return { ok: true, newPairId };
}
