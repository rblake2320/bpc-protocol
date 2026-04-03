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
  return b64url(sig).substring(0, 16);
}

export async function verifySecretHmac(
  secretHash: string,
  nonce: string,
  timestamp: number,
  providedHmac: string
): Promise<boolean> {
  // Server cannot recompute HMAC without plaintext secret.
  // This function is a placeholder that documents the design constraint:
  // The server must store an HKDF-derived key at pairing time (not implemented yet — v0.2.0).
  // For v0.1.0, this check is performed client-side in the demo only.
  void secretHash; void nonce; void timestamp; void providedHmac;
  throw new Error('verifySecretHmac: Server-side HMAC verification requires HKDF key storage (v0.2.0). See spec/bpc-spec-v1.md \u00A76.');
}
