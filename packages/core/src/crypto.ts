import { b64url, b64urlDecode } from './encoding.js';
import type { BPCKeypair } from './types.js';

export async function generateKeypair(): Promise<BPCKeypair> {
  const kp = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,  // non-extractable private key
    ['sign', 'verify']
  );
  const pubJwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
  const fingerprint = await computeFingerprint(pubJwk);
  return { privateKey: kp.privateKey, publicKey: kp.publicKey, pubJwk, fingerprint };
}

export async function computeFingerprint(jwk: JsonWebKey): Promise<string> {
  const data = new TextEncoder().encode(JSON.stringify(jwk));
  const hash = await crypto.subtle.digest('SHA-256', data);
  return b64url(hash).substring(0, 20);
}

export async function signPayload(
  privateKey: CryptoKey,
  payload: Record<string, unknown>
): Promise<string> {
  const { canonicalize } = await import('./canonical.js');
  const data = new TextEncoder().encode(canonicalize(payload));
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, data);
  return b64url(sig);
}

export async function verifyPayload(
  publicKey: CryptoKey,
  payload: Record<string, unknown>,
  signature: string
): Promise<boolean> {
  try {
    const { canonicalize } = await import('./canonical.js');
    const data = new TextEncoder().encode(canonicalize(payload));
    const sigBuf = b64urlDecode(signature);
    return await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      publicKey,
      sigBuf,
      data
    );
  } catch {
    return false;
  }
}

export async function importPublicKeyFromJwk(jwk: JsonWebKey): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['verify']
  );
}
