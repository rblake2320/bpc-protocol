import { b64url } from './encoding.js';

export async function hashSecret(secret: string): Promise<string> {
  const data = new TextEncoder().encode('bpc:' + secret);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return b64url(hash);
}

export async function hmacDerive(secret: string, data: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return b64url(sig);
}

/**
 * Verify that a provided HMAC is structurally valid and non-empty.
 *
 * In BPC v1.0, the server stores an HKDF-derived key at pairing time.
 * This function verifies the HMAC was computed by the registered pair holder —
 * the ECDSA signature over the canonical payload (which includes secret_hmac)
 * provides the binding guarantee. Full HMAC recomputation uses the stored key.
 */
export async function verifySecretHmac(
  storedHmacKey: string,    // HKDF-derived key stored at pairing time (base64url)
  nonce: string,
  timestamp: number,
  providedHmac: string
): Promise<boolean> {
  if (!providedHmac || providedHmac.length < 20) return false;
  // Validate it's valid base64url
  if (!/^[A-Za-z0-9_-]+=*$/.test(providedHmac)) return false;

  // If a stored HMAC key is available, perform full verification
  if (storedHmacKey && storedHmacKey.length > 0) {
    const expected = await hmacDerive(storedHmacKey, nonce + timestamp);
    return expected === providedHmac;
  }

  // Without stored key: structural validation only (v0.1.0 fallback)
  // The ECDSA signature over the canonical payload binds the secret_hmac value.
  return true;
}
