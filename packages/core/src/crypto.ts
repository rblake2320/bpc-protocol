import { b64url, b64urlDecode } from './encoding.js';
import type { BPCKeypair } from './types.js';
import { emitKeyGenerationCapture } from './runtime-capture.js';
import type { KeyGenerationCaptureOptions } from './runtime-capture.js';

export async function generateKeypair(options: KeyGenerationCaptureOptions = {}): Promise<BPCKeypair> {
  const kp = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,  // non-extractable private key
    ['sign', 'verify']
  );
  const pubJwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
  const fingerprint = await computeFingerprint(pubJwk);
  emitKeyGenerationCapture({
    protocol: 'bpc',
    packageName: '@bpc/core',
    event: 'bpc.keypair.generated',
    keyFingerprint: fingerprint,
    algorithm: 'ECDSA P-256',
    extractable: false,
    runtime: options.runtimeMetadata,
    details: {
      publicKeyType: pubJwk.kty,
      curve: pubJwk.crv,
      ...options.captureDetails,
    },
  });
  return { privateKey: kp.privateKey, publicKey: kp.publicKey, pubJwk, fingerprint };
}

export async function computeFingerprint(jwk: JsonWebKey): Promise<string> {
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.x || !jwk.y) {
    throw new TypeError('BPC fingerprint requires an EC P-256 public JWK');
  }
  // Required-member canonicalization ignores runtime-added metadata such as
  // ext/key_ops so Python and WebCrypto produce the same fingerprint.
  const data = new TextEncoder().encode(JSON.stringify({
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y,
  }));
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
