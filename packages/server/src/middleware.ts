/**
 * BPC Request Verification Middleware — 12-step pipeline + Layer 8 Active Defense
 *
 * IL4-7 hardening applied:
 *  - Step 6.5: secretHash fallback removed (BPC-01 fix) — empty secretHash
 *    is now a hard failure at the middleware level (defense in depth alongside
 *    the verifySecretHmac fix and the registry registration validation).
 *  - Step 6: payload parsing validates nonce format (UUID) and timestamp type
 *    before HMAC verification to prevent type-confusion attacks.
 *  - Step 2: pairId format validated against expected pattern.
 *  - Global: method and path validated against allowlists before processing.
 *
 * Layer 8 Active Defense:
 *  - Ghost Pair detection: canary credentials trigger CRITICAL alert + shadow response
 *  - Shadow Mode: locked/ghost pairs return deceptive ok:true with fake session token
 *    SCOPED to sourceIP + pairId — legitimate users on different IPs are unaffected
 *  - Cryptographic Tarpit: graduated delays per source IP applied BEFORE response
 *    (suspicious=500ms, shadow=2000ms) to occupy attacker connection pools
 *
 * Pipeline steps:
 *   rate-limit → headers → version → pair-exists → [ghost-check] → pair-status →
 *   [shadow-check] → decode-payload → hmac → timestamp → nonce → method/path →
 *   scope → body-hash → signature → [tarpit] → success
 *
 * NIST SP 800-53 Rev 5 controls: IA-3, IA-5, SC-8, SC-13, SI-10, AU-2.
 */

import { verifyPayload, importPublicKeyFromJwk, BPC_PROTOCOL_VERSION, verifySecretHmac, assertNoForbiddenKeys } from '@bpc/core';
import type { BPCVerifyResult } from './types.js';
import { TARPIT_DELAY_MS } from './types.js';
import type { PairRegistry } from './registry.js';
import type { ServerNonceStore } from './nonce-store.js';
import type { AnomalyEngine } from './anomaly.js';
import type { RateLimiter } from './rate-limiter.js';
import type { AuditLog } from './audit.js';
import { randomBytes } from 'node:crypto';

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
  rateLimiter?: RateLimiter;      // optional — if omitted, rate limiting is skipped
  auditLog?: AuditLog;            // optional — if omitted, no audit logging
  /**
   * Layer 8: Enable Shadow Mode for locked pairs.
   * When true, locked pairs return ok:true with shadow:true instead of 'pair_locked'.
   * Default: true (recommended for production).
   */
  enableShadowMode?: boolean;
  /**
   * Layer 8: Enable Cryptographic Tarpit.
   * When true, suspicious/shadow IPs receive graduated response delays.
   * Default: true (recommended for production).
   */
  enableTarpit?: boolean;
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

/**
 * Layer 8: Generate a structurally valid but cryptographically inert fake session token.
 * Returned to attackers in shadow/ghost mode so they believe they succeeded.
 * Tagged with shadowToken:true internally — downstream services MUST filter these.
 */
function generateShadowToken(): string {
  // Looks like a real JWT structure but is cryptographically meaningless
  const header  = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({
    sub: randomBytes(16).toString('hex'),
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 3600,
    shadowToken: true,   // INTERNAL TAG — never expose to client
  })).toString('base64url');
  const sig = randomBytes(32).toString('base64url');
  return `${header}.${payload}.${sig}`;
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
      // Layer 8: Record per-IP sig failure for shadow state transitions
      if (pairId) await anomaly.recordSigFailureForIp(pairId, sourceIp);
    }
    await config.auditLog?.write({ action: 'verify_fail', pairId, error, ip: req.ip, method: req.method, path: req.path });
    if (pairId && doSigFail) await registry.recordActivity(pairId, false, sourceIp);
    return { ok: false, error };
  }

  // ── Layer 8: Check if this sourceIP+pairId is already in shadow state ──────
  // This check runs BEFORE all other checks so that attackers in shadow state
  // never learn anything about the pair's actual status.
  if (shadowEnabled && pairId && anomaly.isInShadowState(pairId, sourceIp)) {
    const delayMs = tarpitEnabled ? await anomaly.applyTarpit(sourceIp, 'shadow') : 0;
    const shadowToken = generateShadowToken();
    await config.auditLog?.write({
      action: 'shadow_mode_hit',
      pairId,
      ip: req.ip,
      method: req.method,
      path: req.path,
      severity: 'CRITICAL',
      detail: `Shadow mode active for IP ${sourceIp} on pair ${pairId}`,
    });
    return { ok: true, pairId, shadow: true, tarpitDelayMs: delayMs };
  }

  // Step 1: Rate limit check
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

  // ── Layer 8: Ghost Pair detection ─────────────────────────────────────────
  // If this is a ghost pair (canary token), the credentials are real and will
  // pass all verification steps. We intercept here — AFTER confirming the pair
  // exists — so the attacker's request is fully processed before we trap them.
  // We complete the full verification pipeline first, then return shadow response.
  // (Detection happens at the end of the pipeline — see ghost check below.)

  // Step 5: Pair status checks
  // Layer 8 Shadow Mode: locked pairs return deceptive ok:true instead of 'pair_locked'
  if (pair.status === 'revoked') return deny('pair_revoked');
  if (pair.status === 'locked') {
    if (shadowEnabled) {
      // Enter shadow state for this IP+pair combination
      await anomaly.enterShadowState(req.pairId, sourceIp, 'pair_locked');
      const delayMs = tarpitEnabled ? await anomaly.applyTarpit(sourceIp, 'shadow') : 0;
      await config.auditLog?.write({
        action: 'shadow_mode_enter',
        pairId: req.pairId,
        ip: req.ip,
        method: req.method,
        path: req.path,
        severity: 'HIGH',
        detail: `Locked pair ${req.pairId} — attacker IP ${sourceIp} routed to shadow mode`,
      });
      return { ok: true, pairId: req.pairId, shadow: true, tarpitDelayMs: delayMs };
    }
    return deny('pair_locked');
  }
  if (pair.status === 'rotated') return deny('pair_rotated');
  if (pair.status === 'expired') return deny('pair_expired');

  // Belt-and-suspenders lockout: check failedSigs directly
  const lockoutCount = config.lockoutCount ?? 10;
  if (pair.failedSigs >= lockoutCount) {
    registry.recordActivity(req.pairId, false, sourceIp).catch(() => {});
    if (shadowEnabled) {
      await anomaly.enterShadowState(req.pairId, sourceIp, 'failedSigs_threshold');
      const delayMs = tarpitEnabled ? await anomaly.applyTarpit(sourceIp, 'shadow') : 0;
      return { ok: true, pairId: req.pairId, shadow: true, tarpitDelayMs: delayMs };
    }
    return deny('pair_locked');
  }

  // Check expiresAt field too
  if (pair.expiresAt && Date.now() > pair.expiresAt) {
    pair.status = 'expired';
    registry.get(req.pairId).then(p => { if (p) { p.status = 'expired'; } }).catch(() => {});
    return deny('pair_expired');
  }
  if (pair.status !== 'active') return deny('pair_revoked');

  // ── Layer 8: Tarpit for suspicious IPs (before heavy crypto work) ─────────
  // Check the anomaly verdict for this sourceIP+pairId.
  // Apply tarpit delay BEFORE the expensive signature verification.
  // This burns the attacker's connection pool without wasting our crypto resources.
  let tarpitDelayApplied = 0;
  if (tarpitEnabled && sourceIp !== 'unknown') {
    const verdict = await anomaly.getVerdict(req.pairId, sourceIp);
    if (verdict === 'suspicious') {
      tarpitDelayApplied = await anomaly.applyTarpit(sourceIp, 'suspicious');
    } else if (verdict === 'shadow') {
      // Should have been caught by the shadow state check above, but belt-and-suspenders
      await anomaly.enterShadowState(req.pairId, sourceIp, 'verdict_shadow');
      tarpitDelayApplied = await anomaly.applyTarpit(sourceIp, 'shadow');
      return { ok: true, pairId: req.pairId, shadow: true, tarpitDelayMs: tarpitDelayApplied };
    } else if (verdict === 'attack') {
      return deny('rate_limit_exceeded');
    }
  }

  // Step 6: Decode and parse canonical payload
  // BPC-07 FIX: Scan raw JSON for forbidden keys BEFORE JSON.parse() runs.
  let payload: Record<string, unknown>;
  try {
    const padded = req.signedData.replace(/-/g, '+').replace(/_/g, '/');
    const padLen = (4 - padded.length % 4) % 4;
    const json = atob(padded + '='.repeat(padLen));
    assertNoForbiddenKeys(json); // throws TypeError on any forbidden key
    payload = JSON.parse(json);
  } catch {
    return deny('invalid_signed_data', true);
  }

  // Step 6.5: Validate payload field types before HMAC verification.
  const rawNonce     = payload['nonce'];
  const rawTimestamp = payload['timestamp'];
  if (typeof rawNonce !== 'string' || !UUID_RE.test(rawNonce)) {
    return deny('invalid_signed_data', true);
  }
  if (typeof rawTimestamp !== 'number' || !Number.isFinite(rawTimestamp)) {
    return deny('invalid_signed_data', true);
  }

  // Step 6.6: Verify user-secret HMAC (Layer 3 enforcement)
  const secretHmac = payload['secret_hmac'] as string | undefined;
  if (!secretHmac) {
    return deny('missing_secret_hmac', true);
  }
  if (!pair.secretHash || pair.secretHash.length === 0) {
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

  // Step 7: Timestamp within window
  const now = Date.now();
  if (Math.abs(now - rawTimestamp) > config.sigWindowMs) {
    await anomaly.recordExpiredTimestamp(req.pairId);
    return deny('timestamp_expired', true);
  }

  // Step 8: Nonce not seen before
  if (await nonceStore.checkAndConsume(rawNonce)) {
    await anomaly.recordReplay(req.pairId);
    return deny('replay_detected');
  }

  // Step 9: Method and path match
  if (payload['method'] !== req.method || payload['path'] !== req.path) {
    return deny('method_path_mismatch', true);
  }

  // Step 10: Scope enforcement
  const normalizedWireMethod = req.method.toUpperCase();
  const payloadMethod = typeof payload['method'] === 'string'
    ? payload['method'].toUpperCase()
    : '';
  const allowedMethods = SCOPE_ALLOWED_METHODS[pair.scope] ?? SCOPE_ALLOWED_METHODS['read'];
  if (!allowedMethods.has(normalizedWireMethod) || !allowedMethods.has(payloadMethod)) {
    return deny('scope_violation');
  }

  // Step 11: Body hash verification
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

  // ── Layer 8: Ghost Pair post-verification trap ────────────────────────────
  // The credentials were real and passed ALL verification steps.
  // Now we check if this is a ghost pair (canary token).
  // We complete verification first so the attacker's request is fully processed
  // before we trap them — they cannot tell they triggered a canary.
  if (pair.kind === 'ghost') {
    // Auto-route this source IP to Shadow Mode immediately
    await anomaly.enterShadowState(req.pairId, sourceIp, `ghost_pair_hit:${pair.canaryClass}`);
    const delayMs = tarpitEnabled ? await anomaly.applyTarpit(sourceIp, 'shadow') : 0;

    // Log CRITICAL breach alert with full forensic detail
    await config.auditLog?.write({
      action: 'ghost_pair_triggered',
      pairId: req.pairId,
      ip: req.ip,
      method: req.method,
      path: req.path,
      severity: 'CRITICAL',
      detail: JSON.stringify({
        canaryClass: pair.canaryClass,
        sourceIp,
        method: req.method,
        path: req.path,
        timestamp: now,
        alert: 'CONFIRMED_BREACH — canary credential used. Attacker IP auto-routed to shadow mode.',
      }),
    });

    // Return deceptive success — attacker believes they authenticated.
    // SECURITY: ghostAlert and canaryClass are NEVER returned to the caller.
    // The wire response is indistinguishable from a legitimate shadow-mode response.
    // All forensic data is written exclusively to the audit log above.
    return {
      ok: true,
      pairId: req.pairId,
      shadow: true,
      tarpitDelayMs: delayMs,
    };
  }

  // All checks passed — legitimate request
  await registry.recordActivity(req.pairId, true);
  await config.auditLog?.write({
    action: 'verify_pass',
    pairId: req.pairId,
    method: req.method,
    path: req.path,
    ip: req.ip,
  });

  return {
    ok: true,
    pairId: req.pairId,
    pair,
    tarpitDelayMs: tarpitDelayApplied > 0 ? tarpitDelayApplied : undefined,
  };
}
