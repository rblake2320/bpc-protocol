import argon2 from 'argon2';

export const MIN_SECRET_LENGTH = 8;
export const MAX_SECRET_LENGTH = 64;

/** Argon2id parameters — OWASP recommended minimum */
const ARGON2_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 65536,  // 64 MiB
  timeCost: 3,
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
  if (!/[^A-Za-z0-9]/.test(secret)) return { valid: false, reason: 'Secret must contain at least one special character' };
  return { valid: true };
}
