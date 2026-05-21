/**
 * BPC Admin Endpoint Authentication
 *
 * IL4-7 hardening — Chain-3 / BPC-04 fix:
 *
 * The /bpc/pairs, /bpc/anomaly, and /bpc/audit endpoints MUST be protected
 * by authentication. This module provides:
 *
 *   1. `AdminAuthConfig` — configuration for admin endpoint authentication.
 *      Supports static bearer token (for simple deployments) and a custom
 *      async verifier function (for production deployments using JWT, mTLS,
 *      OIDC, or any other mechanism).
 *
 *   2. `verifyAdminRequest()` — checks an incoming request against the
 *      configured admin auth policy. Returns true if the request is authorized.
 *
 * NIST SP 800-53 Rev 5 controls: AC-2, AC-3, AC-6, IA-3, IA-5.
 *
 * Usage:
 *   const adminAuth: AdminAuthConfig = {
 *     // Option A: static bearer token (suitable for IL4, internal tools)
 *     bearerToken: process.env.BPC_ADMIN_TOKEN,
 *
 *     // Option B: custom async verifier (suitable for IL5-7, production)
 *     verifier: async (req) => {
 *       const token = req.headers['authorization']?.replace('Bearer ', '');
 *       return await verifyJwt(token, process.env.JWKS_URI);
 *     },
 *   };
 *
 *   // In your HTTP handler:
 *   if (!(await verifyAdminRequest(req.headers, adminAuth))) {
 *     return json(res, 401, { error: 'unauthorized' });
 *   }
 */

/** Minimal request shape needed for admin auth — avoids coupling to Node.js http types. */
export interface AdminRequestHeaders {
  authorization?: string;
  [key: string]: string | string[] | undefined;
}

export interface AdminAuthConfig {
  /**
   * Static bearer token.
   * The incoming `Authorization: Bearer <token>` header must match this value.
   * Use a cryptographically random token of at least 32 bytes (256 bits).
   * Suitable for IL4 internal deployments. For IL5-7, use `verifier` instead.
   */
  bearerToken?: string;

  /**
   * Custom async verifier.
   * Called with the request headers. Return true to allow, false to deny.
   * Use this for JWT, mTLS, OIDC, or any other production auth mechanism.
   * When both `bearerToken` and `verifier` are set, BOTH must pass.
   */
  verifier?: (headers: AdminRequestHeaders) => Promise<boolean>;
}

/**
 * Verify an incoming admin request against the configured auth policy.
 *
 * Returns true if the request is authorized, false otherwise.
 * If no config is provided, ALL requests are denied (fail-closed).
 */
export async function verifyAdminRequest(
  headers: AdminRequestHeaders,
  config?: AdminAuthConfig,
): Promise<boolean> {
  // Fail-closed: no config means no access.
  if (!config) return false;

  // Bearer token check
  if (config.bearerToken !== undefined) {
    const authHeader = headers['authorization'];
    if (typeof authHeader !== 'string') return false;
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : authHeader;
    if (token !== config.bearerToken) return false;
  }

  // Custom verifier check
  if (config.verifier) {
    const allowed = await config.verifier(headers);
    if (!allowed) return false;
  }

  // At least one auth mechanism must be configured
  if (!config.bearerToken && !config.verifier) return false;

  return true;
}
