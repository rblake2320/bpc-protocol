/**
 * BPC Request Verification Middleware — 12-step pipeline
 *
 * IL4-7 hardening applied:
 *  - Step 0: Pre-authentication IP rate limiting via `ipRateLimiter` config field.
 *    This fires BEFORE any BPC header is read, so unauthenticated floods are
 *    throttled at the edge. Separate from the per-pair limiter (`rateLimiter`)
 *    so a flooded IP cannot exhaust the per-pair budget for legitimate users.
 *    (BPC-06 / Chain-5 fix — NIST SP 800-53 SC-5)
 *  - Step 6.5: secretHash fallback removed (BPC-01 fix) — empty secretHash
 *    is now a hard failure at the middleware level (defense in depth alongside
 *    the verifySecretHmac fix and the registry registration validation).
 *  - Step 6: payload parsing validates nonce format (UUID) and timestamp type
 *    before HMAC verification to prevent type-confusion attacks.
 *  - Step 2: pairId format validated against expected pattern.
 *  - Global: method and path validated against allowlists before processing.
 *
 * Pipeline steps:
 *   ip-rate-limit → rate-limit → headers → version → pair-exists → pair-status →
 *   decode-payload → hmac → timestamp → nonce → method/path → scope →
 *   body-hash → signature
 *
 * NIST SP 800-53 Rev 5 controls: IA-3, IA-5, SC-5, SC-8, SC-13, SI-10, AU-2.
 */

import { verifyPayload, importPublicKeyFromJwk, BPC_PROTOCOL_VERSION, verifySecretHmac } from '@bpc/core';
import type { BPCVerifyResult } from './types.js';
import type { PairRegistry } from './registry.js';
import type { ServerNonceStore } from './nonce-store.js';
import type { AnomalyEngine } from './anomaly.js';
import type { RateLimiter } from './rate-limiter.js';
import type { AuditLog } from './audit.js';

export interface BPCRequestData {
  pairId: string | null;
  signedData: string | null;      // base64url-encoded canonical payload JSON
  signature: string | null;
  method: string;
  path: string;
  version: string | null;         // X-BPC-Version header
  bodyHash: string | null;        // SHA-256 of actual request body, base64url, client-provided
  ip?: string;                    // for rate limiting
}

// Maximum header field lengths — prevents Node.js 431 and large-payload DoS.
// ECDSA P-256 DER sig = 64-72 bytes -> ~100 base64url chars. 256 is generous.
// Canonical payload with all fields ~400 bytes -> ~550 base64url chars. 4096 is generous.
const MAX_SIGNED_DATA_LEN = 4096;
const MAX_SIGNATURE_LEN   = 256;
const MAX_PAIR_ID_LEN     = 64;

/** Allowed HTTP methods — reject anything outside this set before processing. */
const ALLOWED_METHODS = new Set(['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE']);

/** UUID v4 regex for nonce format validation. */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export interface BPCServerConfig {
  sigWindowMs: number;
  lockoutCount?: number;          // failed sig threshold before pair is locked (default: 10)
  /**
   * Per-IP rate limiter — fires BEFORE any BPC header is read.
   * Recommended: MemoryRateLimiter(200, 60_000) for unauthenticated endpoints.
   * Separate from `rateLimiter` so IP floods cannot exhaust per-pair budgets.
   * (IL4-7 / BPC-06 fix — NIST SP 800-53 SC-5)
   */
  ipRateLimiter?: RateLimiter;
  /**
   * Per-pair rate limiter — fires after pairId is read from headers.
   * Recommended: MemoryRateLimiter(100, 60_000) for authenticated endpoints.
   */
  rateLimiter?: RateLimiter;
  auditLog?: AuditLog;            // optional — if omitted, no audit logging
}

const DEFAULT_SERVER_CONFIG: BPCServerConfig = { sigWindowMs: 60_000 };

const SCOPE_ALLOWED_METHODS: Record<string, Set<string>> = {
  'read':       new Set(['GET', 'HEAD', 'OPTIONS']),
  'read-write': new Set(['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH']),
  'admin':      new Set(['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE']),
};

export async function verifyBPCRequest(
  req: BPCRequestData,
  registry: PairRegistry,
  nonceStore: ServerNonceStore,
  anomaly: AnomalyEngine,
  config: BPCServerConfig = DEFAULT_SERVER_CONFIG,
): Promise<BPCVerifyResult> {
  const pairId = req.pairId ?? undefined;
  await anomaly.recordRequest(pairId);

  async function deny(error: string, doSigFail = false): Promise<BPCVerifyResult> {
    await anomaly.recordDenied(pairId);
    if (doSigFail) await anomaly.recordSigFailure(pairId);
    await config.auditLog?.write({ action: 'verify_fail', pairId, error, ip: req.ip, method: req.method, path: req.path });
    if (pairId && doSigFail) await registry.recordActivity(pairId, false);
    return { ok: false, error };
  }

  // Step 0: Pre-authentication IP rate limit — fires before any BPC header is read.
  // This is the primary defence against unauthenticated floods (Chain-5 / BPC-06).
  // Must use a separate limiter from the per-pair limiter so that a flooded IP
  // cannot exhaust the per-pair budget for legitimate users on the same IP/NAT.
  if (config.ipRateLimiter && req.ip) {
    const rl = await config.ipRateLimiter.check(`ip:${req.ip}`);
    if (!rl.allowed) return deny('rate_limit_exceeded');
  }

  // Step 1: Per-pair rate limit check (fires after pairId is available from headers).
  if (config.rateLimiter && req.ip) {
    const rl = await config.rateLimiter.check(`ip:${req.ip}`);
    if (!rl.allowed) return deny('rate_limit_exceeded');
  }
  if (config.rateLimiter && req.pairId) {
    const rl = await config.rateLimiter.check(`pair:${req.pairId}`);
    if (!rl.allowed) return deny('rate_limit_exceeded');
  }

  // Step 1b: Method allowlist — reject unknown HTTP methods immediately.
  if (!ALLOWED_METHODS.has(req.method)) {
    return deny('invalid_method');
  }

  // Step 2: Headers present + size guards (prevents Node.js 431 / large-payload DoS)
  if (!req.pairId || !req.signedData || !req.signature) {
    return deny('missing_headers');
  }
  if (req.pairId.length > MAX_PAIR_ID_LEN ||
      req.signedData.length > MAX_SIGNED_DATA_LEN ||
      req.signature.length > MAX_SIGNATURE_LEN) {
    return deny('invalid_signed_data');
  }
  // pairId format: must be alphanumeric + underscore/hyphen only.
  if (!/^[A-Za-z0-9_-]+$/.test(req.pairId)) {
    return deny('invalid_signed_data');
  }

  // Step 3: Protocol version check
  const clientVersion = req.version ?? '1.0';
  if (clientVersion !== BPC_PROTOCOL_VERSION) {
    return deny('version_mismatch');
  }

  // Step 4: Pair exists
  const pair = await registry.get(req.pairId);
  if (!pair) {
    await anomaly.recordUnknownPair();
    return deny('unknown_pair');
  }

  // Step 5: Pair status checks
  if (pair.status === 'revoked') return deny('pair_revoked');
  if (pair.status === 'locked')  return deny('pair_locked');
  if (pair.status === 'rotated') return deny('pair_rotated');
  if (pair.status === 'expired') return deny('pair_expired');
  // Belt-and-suspenders lockout: check failedSigs directly to close the parallel-request
  // race window where multiple concurrent forged-sig requests all pass the status check
  // before any single one has committed the locked status back to the store.
  const lockoutCount = config.lockoutCount ?? 10;
  if (pair.failedSigs >= lockoutCount) {
    registry.recordActivity(req.pairId, false).catch(() => {}); // flush status update
    return deny('pair_locked');
  }
  // Check expiresAt field too
  if (pair.expiresAt && Date.now() > pair.expiresAt) {
    pair.status = 'expired';
    // fire-and-forget status update
    registry.get(req.pairId).then(p => { if (p) { p.status = 'expired'; } }).catch(() => {});
    return deny('pair_expired');
  }
  if (pair.status !== 'active') return deny('pair_revoked');

  // Step 6: Decode and parse canonical payload
  let payload: Record<string, unknown>;
  try {
    const padded = req.signedData.replace(/-/g, '+').replace(/_/g, '/');
    const padLen = (4 - padded.length % 4) % 4;
    const json = atob(padded + '='.repeat(padLen));
    payload = JSON.parse(json);
  } catch {
    return deny('invalid_signed_data', true);
  }

  // Step 6.5: Validate payload field types before HMAC verification.
  // Prevents type-confusion attacks where timestamp or nonce is a non-scalar.
  const rawNonce     = payload['nonce'];
  const rawTimestamp = payload['timestamp'];
  if (typeof rawNonce !== 'string' || !UUID_RE.test(rawNonce)) {
    return deny('invalid_signed_data', true);
  }
  if (typeof rawTimestamp !== 'number' || !Number.isFinite(rawTimestamp)) {
    return deny('invalid_signed_data', true);
  }

  // Step 6.6: Verify user-secret HMAC (Layer 3 enforcement)
  // IL4-7 / BPC-01 defense-in-depth: explicitly reject empty secretHash here
  // in addition to the fix in verifySecretHmac() and registry validation.
  const secretHmac = payload['secret_hmac'] as string | undefined;
  if (!secretHmac) {
    return deny('missing_secret_hmac', true);
  }
  if (!pair.secretHash || pair.secretHash.length === 0) {
    // Pair was registered without a valid secretHash — hard reject.
    return deny('invalid_secret_hmac', true);
  }
  const secretValid = await verifySecretHmac(
    pair.secretHash,
    rawNonce,
    rawTimestamp,
    secretHmac,
  );
  if (!secretValid) {
    return deny('invalid_secret_hmac', true);
  }

  // Step 7: Timestamp within window (rawTimestamp already type-validated above).
  const now = Date.now();
  if (Math.abs(now - rawTimestamp) > config.sigWindowMs) {
    await anomaly.recordExpiredTimestamp(req.pairId);
    return deny('timestamp_expired', true);
  }

  // Step 8: Nonce not seen before (rawNonce already UUID-validated above).
  if (await nonceStore.checkAndConsume(rawNonce)) {
    await anomaly.recordReplay(req.pairId);
    return deny('replay_detected');
  }

  // Step 9: Method and path match
  if (payload['method'] !== req.method || payload['path'] !== req.path) {
    return deny('method_path_mismatch', true);
  }

  // Step 10: Scope enforcement
  const allowedMethods = SCOPE_ALLOWED_METHODS[pair.scope] ?? SCOPE_ALLOWED_METHODS['read'];
  if (!allowedMethods.has(req.method)) {
    return deny('scope_violation');
  }

  // Step 11: Body hash verification (if client provided hash in payload)
  const payloadBodyHash = payload['body_hash'] as string | undefined;
  if (payloadBodyHash) {
    if (!req.bodyHash) return deny('missing_body_hash', true);
    if (payloadBodyHash !== req.bodyHash) return deny('invalid_body_hash', true);
  }

  // Step 12: Verify ECDSA signature over canonical payload
  let valid = false;
  try {
    const publicKey = await importPublicKeyFromJwk(pair.pubJwk);
    valid = await verifyPayload(publicKey, payload, req.signature);
  } catch {
    valid = false;
  }

  if (!valid) {
    return deny('invalid_signature', true);
  }

  // All checks passed
  await registry.recordActivity(req.pairId, true);
  await config.auditLog?.write({ action: 'verify_pass', pairId: req.pairId, method: req.method, path: req.path, ip: req.ip });

  return { ok: true, pairId: req.pairId, pair };
}
