/**
 * BPC Key Rotation Handler
 *
 * Security hardening (IL4-7):
 *
 *  BPC-02 FIX — Rotation DoS (ReferenceError: payload is not defined):
 *    `payload` is now declared in the outer scope so it is accessible after
 *    the try/catch block. Previously it was scoped inside try{}, causing an
 *    unhandled ReferenceError that crashed the entire server process on every
 *    valid rotation request.
 *
 *  Additional hardening:
 *    - All error paths return structured RotationResult instead of throwing.
 *    - Input size limits prevent oversized-payload DoS.
 *    - Strict type validation on all request fields before processing.
 *    - Rotation payload binding validates all required fields.
 *
 *  NIST SP 800-53 Rev 5 controls: IA-3, SC-8, SI-10, SI-11.
 */

import { importPublicKeyFromJwk, verifyPayload, generateId } from '@bpc/core';
import type { PairStore } from './store.js';
import type { StoredPair } from './types.js';

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
const MAX_PAIR_ID_LEN    = 64;
const MAX_SIGNED_DATA_LEN = 4096;
const MAX_SIGNATURE_LEN   = 200;

/**
 * Rotate a pair: verify the old key signs the rotation request, create new pair,
 * mark old pair as 'rotated'.
 */
export async function handleRotation(
  req: RotationRequest,
  store: PairStore,
  sigWindowMs = 60_000,
): Promise<RotationResult> {
  // ── Input validation ─────────────────────────────────────────────────────────────────────────
  if (!req.oldPairId || typeof req.oldPairId !== 'string' ||
      req.oldPairId.length > MAX_PAIR_ID_LEN) {
    return { ok: false, error: 'invalid_request' };
  }
  if (!req.signedData || typeof req.signedData !== 'string' ||
      req.signedData.length > MAX_SIGNED_DATA_LEN) {
    return { ok: false, error: 'invalid_request' };
  }
  if (!req.signature || typeof req.signature !== 'string' ||
      req.signature.length > MAX_SIGNATURE_LEN) {
    return { ok: false, error: 'invalid_request' };
  }
  if (typeof req.timestamp !== 'number' || !Number.isFinite(req.timestamp)) {
    return { ok: false, error: 'invalid_request' };
  }
  if (!req.newPubJwk || typeof req.newPubJwk !== 'object') {
    return { ok: false, error: 'invalid_request' };
  }

  // 1. Timestamp check
  if (Math.abs(Date.now() - req.timestamp) > sigWindowMs) {
    return { ok: false, error: 'timestamp_expired' };
  }

  // 2. Lookup old pair
  const oldPair = await store.get(req.oldPairId);
  if (!oldPair) return { ok: false, error: 'unknown_pair' };
  if (oldPair.status !== 'active') return { ok: false, error: 'pair_not_active' };

  // 3. Decode and parse signed rotation payload
  // BPC-02 FIX: `payload` declared in outer scope — accessible after try/catch.
  let payload: Record<string, unknown>;
  try {
    const padded = req.signedData.replace(/-/g, '+').replace(/_/g, '/');
    const padLen  = (4 - padded.length % 4) % 4;
    const json    = atob(padded + '='.repeat(padLen));
    payload = JSON.parse(json) as Record<string, unknown>;
  } catch {
    return { ok: false, error: 'invalid_signed_data' };
  }

  // 4. Verify ECDSA signature with the OLD key
  let valid = false;
  try {
    const pubKey = await importPublicKeyFromJwk(oldPair.pubJwk);
    valid = await verifyPayload(pubKey, payload, req.signature);
  } catch {
    valid = false;
  }
  if (!valid) return { ok: false, error: 'invalid_signature' };

  // 5. Bind rotation payload to request parameters
  // IL4-7 / BPC-05: new_pub_jwk is transmitted as a JSON string (new_pub_jwk_json)
  // to comply with the flat-scalar-only canonicalization requirement.
  if (payload['purpose']     !== 'rotation')    return { ok: false, error: 'payload_field_mismatch' };
  if (payload['old_pair_id'] !== req.oldPairId) return { ok: false, error: 'payload_field_mismatch' };
  if (payload['timestamp']   !== req.timestamp) return { ok: false, error: 'payload_field_mismatch' };

  // Parse new_pub_jwk_json from the signed payload and compare to the request body.
  const newPubJwkJson = payload['new_pub_jwk_json'] as string | undefined;
  if (!newPubJwkJson || typeof newPubJwkJson !== 'string') {
    return { ok: false, error: 'payload_field_mismatch' };
  }
  let parsedNewPubJwk: JsonWebKey;
  try {
    parsedNewPubJwk = JSON.parse(newPubJwkJson) as JsonWebKey;
  } catch {
    return { ok: false, error: 'invalid_signed_data' };
  }
  if (JSON.stringify(parsedNewPubJwk) !== JSON.stringify(req.newPubJwk)) {
    return { ok: false, error: 'payload_field_mismatch' };
  }

  // 6. Create new pair with same metadata, new public key
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
  await store.set(newPair);

  // 7. Mark old pair as rotated
  oldPair.status = 'rotated';
  await store.set(oldPair);

  return { ok: true, newPairId };
}
