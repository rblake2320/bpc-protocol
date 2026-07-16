/**
 * BPC Request Verification Middleware — 12-step pipeline + Layer 8 Active Defense
 *
 * Security hardening applied:
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
 *  - Issue #6 fix: verifyBPCRequest now returns an immutable AuthSnapshot
 *    instead of the live mutable StoredPair. Concurrent lifecycle mutations
 *    cannot change result.snapshot.scope after authorization.
 *
 * Layer 8 Active Defense:
 *  - Ghost Pair detection: canary credentials trigger a CRITICAL alert and hard denial
 *  - Shadow Mode: locked/ghost pairs remain authorization failures (`ok:false`)
 *    SCOPED to sourceIP + pairId — legitimate users on different IPs are unaffected
 *  - Cryptographic Tarpit: graduated delays per source IP applied BEFORE response
 *    (suspicious=500ms, shadow=2000ms) to occupy attacker connection pools
 *
 * Pipeline steps:
 *   ip-rate-limit → rate-limit → headers → version → pair-exists → [ghost-check] →
 *   pair-status → [shadow-check] → decode-payload → hmac → timestamp → nonce →
 *   method/path → scope → body-hash → signature → [tarpit] → snapshot → success
 *
 * NIST SP 800-53 Rev 5 controls: IA-3, IA-5, SC-5, SC-8, SC-13, SI-10, AU-2.
 */

import { verifyPayload, importPublicKeyFromJwk, BPC_PROTOCOL_VERSION, verifySecretHmac, assertNoForbiddenKeys } from '@bpc/core';
import type { BPCVerifyResult, AuthSnapshot } from './types.js';
import { TARPIT_DELAY_MS } from './types.js';
import type { PairRegistry } from './registry.js';
import type { ServerNonceStore } from './nonce-store.js';
import type { AnomalyEngine } from './anomaly.js';
import type { RateLimiter } from './rate-limiter.js';
import type { AuditLog } from './audit.js';
import { AuthorizationQuarantineError, type ContinuityGate } from './redis-continuity.js';

export interface BPCRequestData {
  pairId: string | null;
  signedData: string | null;      // base64url-encoded canonical payload JSON
  signature: string | null;
  method: string;
  path: string;
  version: string | null;         // X-BPC-Version header
  bodyHash: string | null;        // SHA-256 of actual request body, base64url, client-provided
  ip?: string;                    // for rate limiting and Layer 8 shadow scoping
}

// Maximum header field lengths — prevents Node.js 431 and large-payload DoS.
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
   * (BPC-06 fix; candidate NIST SP 800-53 SC-5 evidence)
   */
  ipRateLimiter?: RateLimiter;
  /**
   * Per-pair rate limiter — fires after pairId is read from headers.
   * Recommended: MemoryRateLimiter(100, 60_000) for authenticated endpoints.
   */
  rateLimiter?: RateLimiter;
  auditLog?: AuditLog;            // optional — if omitted, no audit logging
  /**
   * Layer 8: Enable Shadow Mode for locked pairs.
   * When true, locked pairs are marked shadow:true while still returning ok:false.
   * Default: true (recommended for production).
   */
  enableShadowMode?: boolean;
  /**
   * Layer 8: Enable Cryptographic Tarpit.
   * When true, suspicious/shadow IPs receive graduated response delays.
   * Default: true (recommended for production).
   */
  enableTarpit?: boolean;
  /**
   * Issue #11/#13: continuity gate. When provided, authorization fails closed
   * (deny 'authorization_quarantined') while Redis nonce-state continuity is
   * uncertain — after state loss, ambiguous failover, or an unreachable marker
   * store. Checked immediately before the nonce is consumed. Optional and
   * non-breaking: verifiers without a continuity guard behave as before.
   */
  continuityGuard?: ContinuityGate;
}

const DEFAULT_SERVER_CONFIG: BPCServerConfig = {
  sigWindowMs: 60_000,
  enableShadowMode: true,
  enableTarpit: true,
};

const SCOPE_ALLOWED_METHODS: Record<string, Set<string>> = {
  'read':       new Set(['GET', 'HEAD', 'OPTIONS']),
  'read-write': new Set(['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH']),
  'admin':      new Set(['GET', 'HEAD', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE']),
};

interface AuthorizationContext {
  readonly pairId: string;
  readonly scope: AuthSnapshot['scope'];
  readonly mode: AuthSnapshot['mode'];
  readonly kind: AuthSnapshot['kind'];
  readonly canaryClass?: AuthSnapshot['canaryClass'];
  readonly status: 'active' | 'locked' | 'expired' | 'rotated' | 'revoked';
  readonly failedSigs: number;
  readonly expiresAt?: number;
  readonly maxRequests?: number;
  readonly requests: number;
  readonly secretHash: string;
  readonly pubJwk: JsonWebKey;
}

/**
 * Copy every value used by authorization before the verifier crosses another
 * asynchronous boundary. MemoryPairStore intentionally returns a live object,
 * so retaining StoredPair here would let a concurrent updatePair() change the
 * policy inputs while the request is being verified.
 */
function captureAuthorizationContext(pair: import('./types.js').StoredPair): AuthorizationContext {
  const pubJwk = Object.freeze({
    ...pair.pubJwk,
    key_ops: pair.pubJwk.key_ops ? Object.freeze([...pair.pubJwk.key_ops]) : undefined,
  }) as JsonWebKey;

  return Object.freeze({
    pairId: pair.id,
    scope: pair.scope,
    mode: pair.mode,
    kind: pair.kind ?? 'legitimate',
    canaryClass: pair.canaryClass,
    status: pair.status,
    failedSigs: pair.failedSigs,
    expiresAt: pair.expiresAt,
    maxRequests: pair.maxRequests,
    requests: pair.requests,
    secretHash: pair.secretHash,
    pubJwk,
  });
}

export async function verifyBPCRequest(
  req: BPCRequestData,
  registry: PairRegistry,
  nonceStore: ServerNonceStore,
  anomaly: AnomalyEngine,
  config: BPCServerConfig = DEFAULT_SERVER_CONFIG,
): Promise<BPCVerifyResult> {
  const pairId = req.pairId ?? undefined;
  const sourceIp = req.ip ?? 'unknown';
  const shadowEnabled = config.enableShadowMode !== false;
  const tarpitEnabled = config.enableTarpit !== false;

  await anomaly.recordRequest(pairId);

  async function deny(error: string, doSigFail = false): Promise<BPCVerifyResult> {
    await anomaly.recordDenied(pairId);
    if (doSigFail) {
      await anomaly.recordSigFailure(pairId);
      if (pairId) await anomaly.recordSigFailureForIp(pairId, sourceIp);
    }
    await config.auditLog?.write({ action: 'verify_fail', pairId, error, ip: req.ip, method: req.method, path: req.path });
    if (pairId && doSigFail) await registry.recordActivity(pairId, false, sourceIp);
    return { ok: false, error };
  }

  // Step 0: Pre-authentication IP rate limit
  if (config.ipRateLimiter && req.ip) {
    const rl = await config.ipRateLimiter.check(`ip:${req.ip}`);
    if (!rl.allowed) return deny('rate_limit_exceeded');
  }

  // Layer 8: Shadow state check — runs before all other checks
  if (shadowEnabled && pairId && anomaly.isInShadowState(pairId, sourceIp)) {
    const delayMs = tarpitEnabled ? await anomaly.applyTarpit(sourceIp, 'shadow') : 0;
    await config.auditLog?.write({
      action: 'shadow_mode_hit', pairId, ip: req.ip, method: req.method, path: req.path,
      severity: 'CRITICAL', detail: `Shadow mode active for IP ${sourceIp} on pair ${pairId}`,
    });
    return { ok: false, pairId, error: 'shadow_denied', shadow: true, tarpitDelayMs: delayMs };
  }

  // Step 1: Per-pair rate limit
  if (config.rateLimiter && req.pairId) {
    const rl = await config.rateLimiter.check(`pair:${req.pairId}`);
    if (!rl.allowed) return deny('rate_limit_exceeded');
  }

  // Step 1b: Method allowlist
  if (!ALLOWED_METHODS.has(req.method)) {
    return deny('invalid_method');
  }

  // Step 2: Headers present + size guards
  if (!req.pairId || !req.signedData || !req.signature) {
    return deny('missing_headers');
  }
  if (req.pairId.length > MAX_PAIR_ID_LEN ||
      req.signedData.length > MAX_SIGNED_DATA_LEN ||
      req.signature.length > MAX_SIGNATURE_LEN) {
    return deny('invalid_signed_data');
  }
  if (!/^[A-Za-z0-9_-]+$/.test(req.pairId)) {
    return deny('invalid_signed_data');
  }

  // Step 3: Protocol version
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
  const auth = captureAuthorizationContext(pair);

  // Step 5: Pair status
  if (auth.status === 'revoked') return deny('pair_revoked');
  if (auth.status === 'locked') {
    if (shadowEnabled) {
      await anomaly.enterShadowState(req.pairId, sourceIp, 'pair_locked');
      const delayMs = tarpitEnabled ? await anomaly.applyTarpit(sourceIp, 'shadow') : 0;
      await config.auditLog?.write({
        action: 'shadow_mode_enter', pairId: req.pairId, ip: req.ip,
        method: req.method, path: req.path, severity: 'HIGH',
        detail: `Locked pair ${req.pairId} — attacker IP ${sourceIp} routed to shadow mode`,
      });
      return { ok: false, pairId: req.pairId, error: 'pair_locked', shadow: true, tarpitDelayMs: delayMs };
    }
    return deny('pair_locked');
  }
  if (auth.status === 'rotated') return deny('pair_rotated');
  if (auth.status === 'expired') return deny('pair_expired');

  const lockoutCount = config.lockoutCount ?? 10;
  if (auth.failedSigs >= lockoutCount) {
    registry.recordActivity(req.pairId, false, sourceIp).catch(() => {});
    if (shadowEnabled) {
      await anomaly.enterShadowState(req.pairId, sourceIp, 'failedSigs_threshold');
      const delayMs = tarpitEnabled ? await anomaly.applyTarpit(sourceIp, 'shadow') : 0;
      return { ok: false, pairId: req.pairId, error: 'pair_locked', shadow: true, tarpitDelayMs: delayMs };
    }
    return deny('pair_locked');
  }

  if (auth.expiresAt && Date.now() > auth.expiresAt) {
    pair.status = 'expired';
    registry.get(req.pairId).then(p => { if (p) { p.status = 'expired'; } }).catch(() => {});
    return deny('pair_expired');
  }
  if (auth.maxRequests && auth.maxRequests > 0 && auth.requests >= auth.maxRequests) {
    return deny('pair_usage_cap_exceeded');
  }
  if (auth.status !== 'active') return deny('pair_revoked');

  // Layer 8: Tarpit for suspicious IPs
  let tarpitDelayApplied = 0;
  if (tarpitEnabled && sourceIp !== 'unknown') {
    const verdict = await anomaly.getVerdict(req.pairId, sourceIp);
    if (verdict === 'suspicious') {
      tarpitDelayApplied = await anomaly.applyTarpit(sourceIp, 'suspicious');
    } else if (verdict === 'shadow') {
      await anomaly.enterShadowState(req.pairId, sourceIp, 'verdict_shadow');
      tarpitDelayApplied = await anomaly.applyTarpit(sourceIp, 'shadow');
      return { ok: false, pairId: req.pairId, error: 'shadow_denied', shadow: true, tarpitDelayMs: tarpitDelayApplied };
    } else if (verdict === 'attack') {
      return deny('rate_limit_exceeded');
    }
  }

  // Step 6: Decode and parse canonical payload
  let payload: Record<string, unknown>;
  try {
    const padded = req.signedData.replace(/-/g, '+').replace(/_/g, '/');
    const padLen = (4 - padded.length % 4) % 4;
    const json = atob(padded + '='.repeat(padLen));
    assertNoForbiddenKeys(json);
    payload = JSON.parse(json);
  } catch {
    return deny('invalid_signed_data', true);
  }

  // Step 6.5: Validate payload field types
  const rawNonce     = payload['nonce'];
  const rawTimestamp = payload['timestamp'];
  if (typeof rawNonce !== 'string' || !UUID_RE.test(rawNonce)) {
    return deny('invalid_signed_data', true);
  }
  if (typeof rawTimestamp !== 'number' || !Number.isFinite(rawTimestamp)) {
    return deny('invalid_signed_data', true);
  }

  // Step 6.6: Verify user-secret HMAC (Layer 3)
  const secretHmac = payload['secret_hmac'] as string | undefined;
  if (!secretHmac) {
    return deny('missing_secret_hmac', true);
  }
  if (!auth.secretHash || auth.secretHash.length === 0) {
    return deny('invalid_secret_hmac', true);
  }
  const secretValid = await verifySecretHmac(auth.secretHash, rawNonce, rawTimestamp, secretHmac);
  if (!secretValid) {
    return deny('invalid_secret_hmac', true);
  }

  // Step 7: Timestamp within window
  const now = Date.now();
  if (Math.abs(now - rawTimestamp) > config.sigWindowMs) {
    await anomaly.recordExpiredTimestamp(req.pairId);
    return deny('timestamp_expired', true);
  }

  // Step 8: Method, path, pair_id, version binding
  if (payload['method'] !== req.method || payload['path'] !== req.path) {
    return deny('method_path_mismatch', true);
  }
  if (payload['pair_id'] !== req.pairId) {
    return deny('pair_id_mismatch', true);
  }
  if (payload['version'] !== BPC_PROTOCOL_VERSION) {
    return deny('version_mismatch', true);
  }

  // Step 10: Scope enforcement
  const normalizedWireMethod = req.method.toUpperCase();
  const payloadMethod = typeof payload['method'] === 'string'
    ? payload['method'].toUpperCase()
    : '';
  const allowedMethods = SCOPE_ALLOWED_METHODS[auth.scope];
  if (!allowedMethods) return deny('scope_violation');
  if (!allowedMethods.has(normalizedWireMethod) || !allowedMethods.has(payloadMethod)) {
    return deny('scope_violation');
  }

  // Step 11: Body hash verification
  const payloadBodyHash = payload['body_hash'];
  if (typeof payloadBodyHash !== 'string' || payloadBodyHash.length === 0) {
    return deny('missing_body_hash', true);
  }
  if (!req.bodyHash) return deny('missing_body_hash', true);
  if (payloadBodyHash !== req.bodyHash) return deny('invalid_body_hash', true);

  // Step 12: Verify ECDSA signature
  let valid = false;
  try {
    const publicKey = await importPublicKeyFromJwk(auth.pubJwk);
    valid = await verifyPayload(publicKey, payload, req.signature);
  } catch {
    valid = false;
  }
  if (!valid) {
    return deny('invalid_signature', true);
  }

  // Freeze the result before the first await after final cryptographic
  // verification. Values come from the immutable context used above, never
  // from the live StoredPair object.
  const snapshot: AuthSnapshot = Object.freeze({
    pairId: auth.pairId,
    scope: auth.scope,
    mode: auth.mode,
    kind: auth.kind,
    canaryClass: auth.canaryClass,
    verifiedAt: now,
  });

  // Issue #11/#13: refuse to consume a nonce while continuity is uncertain.
  // If the marker store lost state / failed over, checkAndConsume could accept
  // an already-used nonce; the guard fails closed here instead.
  if (config.continuityGuard) {
    try {
      config.continuityGuard.assertAcceptable();
    } catch {
      return deny('authorization_quarantined');
    }
  }

  // Atomic first-acceptance gate. Concurrent valid replays can both complete
  // signature verification, but only one can consume the nonce.
  let replayDetected: boolean;
  try {
    replayDetected = await nonceStore.checkAndConsume(rawNonce);
  } catch (error) {
    if (error instanceof AuthorizationQuarantineError) {
      return deny('authorization_quarantined');
    }
    return deny('replay_store_unavailable');
  }
  if (replayDetected) {
    await anomaly.recordReplay(req.pairId);
    return deny('replay_detected');
  }

  // Layer 8: Ghost Pair post-verification trap
  if (auth.kind === 'ghost') {
    await anomaly.enterShadowState(req.pairId, sourceIp, `ghost_pair_hit:${auth.canaryClass}`);
    const delayMs = tarpitEnabled ? await anomaly.applyTarpit(sourceIp, 'shadow') : 0;
    await config.auditLog?.write({
      action: 'ghost_pair_triggered', pairId: req.pairId, ip: req.ip,
      method: req.method, path: req.path, severity: 'CRITICAL',
      detail: JSON.stringify({
        canaryClass: auth.canaryClass, sourceIp, method: req.method, path: req.path,
        timestamp: now, alert: 'CONFIRMED_BREACH — canary credential used. Attacker IP auto-routed to shadow mode.',
      }),
    });
    return { ok: false, pairId: req.pairId, error: 'ghost_pair_denied', shadow: true, tarpitDelayMs: delayMs };
  }

  await registry.recordActivity(req.pairId, true);
  await config.auditLog?.write({
    action: 'verify_pass', pairId: req.pairId,
    method: req.method, path: req.path, ip: req.ip,
  });

  return {
    ok: true,
    pairId: req.pairId,
    snapshot,
    tarpitDelayMs: tarpitDelayApplied > 0 ? tarpitDelayApplied : undefined,
  };
}
