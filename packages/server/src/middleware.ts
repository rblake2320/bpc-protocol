/**
 * Core BPC request verification — framework-agnostic.
 *
 * Takes parsed request data, returns a verification result. No HTTP framework coupling.
 *
 * HMAC verification (v0.1.0 design constraint):
 * The secret_hmac field is included in the canonical payload and covered by the
 * ECDSA signature. If the signature verifies, the secret_hmac was produced by the
 * holder of the private key associated with the registered pair. Independent
 * server-side HMAC recomputation (requiring HKDF-derived key storage) is deferred
 * to v0.2.0. See spec/bpc-spec-v1.md section 6.
 */

import { verifyPayload, importPublicKeyFromJwk, canonicalize } from '@bpc/core';
import type { BPCVerifyResult } from './types.js';
import type { PairRegistry } from './registry.js';
import type { ServerNonceStore } from './nonce-store.js';
import type { AnomalyEngine } from './anomaly.js';

export interface BPCRequestData {
  pairId: string | null;
  signedData: string | null;   // base64url-encoded canonical payload JSON
  signature: string | null;
  method: string;
  path: string;
}

export interface BPCServerConfig {
  sigWindowMs: number;
}

const DEFAULT_SERVER_CONFIG: BPCServerConfig = { sigWindowMs: 60_000 };

export async function verifyBPCRequest(
  req: BPCRequestData,
  registry: PairRegistry,
  nonceStore: ServerNonceStore,
  anomaly: AnomalyEngine,
  config: BPCServerConfig = DEFAULT_SERVER_CONFIG
): Promise<BPCVerifyResult> {
  anomaly.recordRequest();

  // 1. Headers present
  if (!req.pairId || !req.signedData || !req.signature) {
    anomaly.recordDenied();
    return { ok: false, error: 'missing_headers' };
  }

  // 2. Pair exists and is active
  const pair = registry.get(req.pairId);
  if (!pair) {
    anomaly.recordUnknownPair();
    anomaly.recordDenied();
    return { ok: false, error: 'unknown_pair' };
  }
  if (pair.status !== 'active') {
    anomaly.recordDenied();
    return { ok: false, error: 'pair_revoked' };
  }

  // 3. Decode and parse canonical payload
  let payload: Record<string, unknown>;
  try {
    const padded = req.signedData.replace(/-/g, '+').replace(/_/g, '/');
    const padLen = (4 - padded.length % 4) % 4;
    const json = atob(padded + '='.repeat(padLen));
    payload = JSON.parse(json);
  } catch {
    anomaly.recordSigFailure();
    anomaly.recordDenied();
    return { ok: false, error: 'invalid_signed_data' };
  }

  // 4. Timestamp within window
  const ts = payload['timestamp'] as number;
  const now = Date.now();
  if (typeof ts !== 'number' || Math.abs(now - ts) > config.sigWindowMs) {
    anomaly.recordExpiredTimestamp();
    anomaly.recordDenied();
    registry.recordActivity(req.pairId, false);
    return { ok: false, error: 'timestamp_expired' };
  }

  // 5. Nonce not seen before
  const nonce = payload['nonce'] as string;
  if (!nonce || nonceStore.checkAndConsume(nonce)) {
    anomaly.recordReplay();
    anomaly.recordDenied();
    return { ok: false, error: 'replay_detected' };
  }

  // 6. Method and path match
  if (payload['method'] !== req.method || payload['path'] !== req.path) {
    anomaly.recordSigFailure();
    anomaly.recordDenied();
    registry.recordActivity(req.pairId, false);
    return { ok: false, error: 'method_path_mismatch' };
  }

  // 7. Verify ECDSA signature over canonical payload
  let valid = false;
  try {
    const publicKey = await importPublicKeyFromJwk(pair.pubJwk);
    valid = await verifyPayload(publicKey, payload, req.signature);
  } catch {
    valid = false;
  }

  if (!valid) {
    anomaly.recordSigFailure();
    anomaly.recordDenied();
    registry.recordActivity(req.pairId, false);
    return { ok: false, error: 'invalid_signature' };
  }

  // 8. All checks passed
  registry.recordActivity(req.pairId, true);
  return { ok: true, pairId: req.pairId, pair };
}
