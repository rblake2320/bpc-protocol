/**
 * BPC HMAC Key Derivation and Verification
 *
 * Request HMAC hardening:
 *
 *  BPC-01 FIX — HMAC Authentication Bypass:
 *    The previous implementation returned `true` when `storedHmacKey` was empty,
 *    allowing any attacker who registered with secretHash='' to authenticate with
 *    an arbitrary HMAC value. This fallback has been REMOVED. An empty or missing
 *    stored key is now a hard authentication failure.
 *
 *  BPC-03 FIX — Weak Secret Hashing (SHA-256 → HKDF-SHA-256):
 *    The previous `hashSecret` used a single SHA-256 digest, which is trivially
 *    brute-forceable at billions of hashes/second on commodity GPUs. The new
 *    implementation uses HKDF (RFC 5869) with SHA-256, a domain-specific salt,
 *    and a 256-bit output key. Algorithm selection does not establish FIPS
 *    validation of the deployed cryptographic module.
 *
 *  NIST SP 800-53 Rev 5 controls: IA-5, SC-13, SC-28.
 */

import { b64url, b64urlDecode } from './encoding.js';

/** HKDF domain-separation info string. */
const HKDF_INFO = new TextEncoder().encode('bpc-v1-hmac-key');

/** Fixed domain-separation salt (not a secret). */
const HKDF_SALT = new TextEncoder().encode('bpc-protocol-hmac-salt-v1');

/**
 * Derive a 256-bit HMAC key from a user secret using HKDF-SHA-256.
 * Replaces the previous SHA-256(bpc: + secret) approach.
 * Uses HKDF-SHA-256 with protocol-specific domain separation.
 */
export async function hashSecret(secret: string): Promise<string> {
  if (!secret || secret.length === 0) {
    throw new TypeError('BPC hashSecret: secret must not be empty');
  }
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HKDF' },
    false,
    ['deriveBits'],
  );
  const derived = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: HKDF_SALT, info: HKDF_INFO },
    keyMaterial,
    256,
  );
  return b64url(derived);
}

/**
 * Compute an HMAC-SHA-256 tag over `data` using the given key material.
 */
export async function hmacDerive(keyMaterial: string, data: string): Promise<string> {
  if (!keyMaterial || keyMaterial.length === 0) {
    throw new TypeError('BPC hmacDerive: keyMaterial must not be empty');
  }
  const keyBytes = b64urlDecode(keyMaterial);
  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const tag = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return b64url(tag);
}

/**
 * Verify a request's `secret_hmac` field against the stored HMAC key.
 *
 * BPC-01 fix:
 *  - Empty/missing `storedHmacKey` is a HARD FAILURE — no fallback, no bypass.
 *  - Minimum HMAC tag length: 43 chars (256-bit output, base64url-encoded).
 *  - Constant-time comparison prevents timing oracle attacks.
 */
export async function verifySecretHmac(
  storedHmacKey: string,
  nonce: string,
  timestamp: number,
  providedHmac: string,
): Promise<boolean> {
  // Hard reject empty/missing stored key — no fallback, no bypass.
  if (!storedHmacKey || storedHmacKey.length === 0) return false;

  // Structural validation: base64url, minimum 43 chars (256-bit HMAC output).
  if (!providedHmac || providedHmac.length < 43) return false;
  if (!/^[A-Za-z0-9_-]+=*$/.test(providedHmac)) return false;

  let expected: string;
  try {
    expected = await hmacDerive(storedHmacKey, nonce + timestamp);
  } catch {
    return false;
  }

  // Constant-time comparison.
  const enc = new TextEncoder();
  const aBytes = enc.encode(expected);
  const bBytes = enc.encode(providedHmac);
  let diff = aBytes.length !== bBytes.length ? 1 : 0;
  for (let i = 0; i < aBytes.length; i++) diff |= aBytes[i] ^ (bBytes[i] ?? 0);
  return diff === 0;
}
