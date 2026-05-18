/**
 * BPC Secret Hashing and Validation
 *
 * IL4-7 hardening:
 *  - Argon2id parameters increased to NIST SP 800-63B / OWASP Level 2 for
 *    IL4-7 environments: 128 MiB memory, 4 iterations, 4 parallelism.
 *  - MIN_SECRET_LENGTH increased from 8 to 16 characters.
 *  - MAX_SECRET_LENGTH increased from 64 to 128 characters.
 *  - Password policy strengthened: minimum 2 special characters.
 *
 * NIST SP 800-53 Rev 5 controls: IA-5 (Authenticator Management).
 * NIST SP 800-63B Section 5.1.1 (Memorized Secret Authenticators).
 */

import argon2 from 'argon2';

export const MIN_SECRET_LENGTH = 16;
export const MAX_SECRET_LENGTH = 128;

/**
 * Argon2id parameters for IL4-7 environments.
 * Exceeds OWASP minimum (64 MiB / t=3) and aligns with NIST SP 800-63B Level 2.
 */
const ARGON2_OPTIONS = {
  type:        argon2.argon2id,
  memoryCost:  131072,  // 128 MiB (IL4-7 level)
  timeCost:    4,       // 4 iterations
  parallelism: 4,
} as const;

/**
 * Hash a user secret for server-side storage.
 * Uses Argon2id — safe against GPU/ASIC brute-force attacks.
 * Returns the encoded hash string (includes salt, params).
 */
export async function hashSecretForStorage(secret: string): Promise<string> {
  return argon2.hash(secret, ARGON2_OPTIONS);
}

/**
 * Verify a plaintext secret against a stored Argon2id hash.
 */
export async function verifyStoredSecret(secret: string, hash: string): Promise<boolean> {
  return argon2.verify(hash, secret);
}

/**
 * Validate a secret meets BPC requirements.
 * Returns { valid: true } or { valid: false, reason: string }.
 */
export function validateSecret(secret: string): { valid: boolean; reason?: string } {
  if (typeof secret !== 'string') return { valid: false, reason: 'Secret must be a string' };
  if (secret.length < MIN_SECRET_LENGTH) return { valid: false, reason: `Secret must be at least ${MIN_SECRET_LENGTH} characters` };
  if (secret.length > MAX_SECRET_LENGTH) return { valid: false, reason: `Secret must be at most ${MAX_SECRET_LENGTH} characters` };
  if (!/[A-Z]/.test(secret)) return { valid: false, reason: 'Secret must contain at least one uppercase letter' };
  if (!/[a-z]/.test(secret)) return { valid: false, reason: 'Secret must contain at least one lowercase letter' };
  if (!/[0-9]/.test(secret)) return { valid: false, reason: 'Secret must contain at least one digit' };
  // IL4-7: require at least 2 special characters for stronger entropy.
  const specialCount = (secret.match(/[^A-Za-z0-9]/g) ?? []).length;
  if (specialCount < 2) return { valid: false, reason: 'Secret must contain at least two special characters' };
  return { valid: true };
}
