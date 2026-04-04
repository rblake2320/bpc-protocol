import { importPublicKeyFromJwk, verifyPayload, generateId } from '@bpc/core';
import type { PairStore } from './store.js';
import type { StoredPair } from './types.js';

export interface RotationRequest {
  oldPairId: string;
  newPubJwk: JsonWebKey;
  /** ECDSA signature over canonicalized { old_pair_id, new_pub_jwk, timestamp } */
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

/**
 * Rotate a pair: verify the old key signs the rotation request, create new pair,
 * mark old pair as 'rotated'.
 */
export async function handleRotation(
  req: RotationRequest,
  store: PairStore,
  sigWindowMs = 60_000,
): Promise<RotationResult> {
  // 1. Timestamp check
  if (Math.abs(Date.now() - req.timestamp) > sigWindowMs) {
    return { ok: false, error: 'timestamp_expired' };
  }

  // 2. Lookup old pair
  const oldPair = await store.get(req.oldPairId);
  if (!oldPair) return { ok: false, error: 'unknown_pair' };
  if (oldPair.status !== 'active') return { ok: false, error: 'pair_not_active' };

  // 3. Verify signature with OLD key
  let valid = false;
  try {
    const pubKey = await importPublicKeyFromJwk(oldPair.pubJwk);
    // signedData is base64url-encoded JSON of the rotation payload
    const padded = req.signedData.replace(/-/g, '+').replace(/_/g, '/');
    const padLen = (4 - padded.length % 4) % 4;
    const json = atob(padded + '='.repeat(padLen));
    const payload = JSON.parse(json) as Record<string, unknown>;
    valid = await verifyPayload(pubKey, payload, req.signature);
  } catch {
    valid = false;
  }

  if (!valid) return { ok: false, error: 'invalid_signature' };

  // 4. Create new pair with same metadata, new public key
  const newPairId = generateId('pair');
  const newPair: StoredPair = {
    id: newPairId,
    name: oldPair.name,
    scope: oldPair.scope,
    mode: oldPair.mode,
    secretHash: oldPair.secretHash,
    pubJwk: req.newPubJwk,
    status: 'active',
    created: Date.now(),
    lastActive: null,
    requests: 0,
    failedSigs: 0,
    expiresAt: oldPair.expiresAt,
  };

  await store.set(newPair);

  // 5. Mark old pair as rotated
  oldPair.status = 'rotated';
  await store.set(oldPair);

  return { ok: true, newPairId };
}
