import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import path from 'node:path';

import {
  b64url,
  canonicalize,
  computeFingerprint,
  generateKeypair,
  hashSecret,
  hmacDerive,
  importPublicKeyFromJwk,
  signPayload,
  verifyPayload,
  verifySecretHmac,
} from './packages/core/src/index.js';

const pythonPath = path.resolve('packages/bpc-client');
const environment = { ...process.env, PYTHONPATH: pythonPath };
const secret = 'CrossLanguageSecret1!@';

const pythonSigner = String.raw`
import json
from bpc_client.crypto import generate_keypair, sign_request

secret = "CrossLanguageSecret1!@"
kp = generate_keypair()
headers = sign_request(kp["private_key"], "pair_cross_language", secret, "POST", "/interop", b"{}")
print(json.dumps({"pubJwk": kp["public_key_jwk"], "fingerprint": kp["fingerprint"], "headers": headers}))
`;

const pythonResult = spawnSync('python', ['-c', pythonSigner], {
  cwd: process.cwd(),
  encoding: 'utf8',
  env: environment,
});
if (pythonResult.status !== 0) throw new Error(`Python signer failed: ${pythonResult.stderr}`);

const fromPython = JSON.parse(pythonResult.stdout) as {
  pubJwk: JsonWebKey;
  fingerprint: string;
  headers: Record<string, string>;
};
const pythonPayload = JSON.parse(
  Buffer.from(fromPython.headers['X-BPC-Signed-Data'], 'base64url').toString('utf8'),
) as Record<string, unknown>;
const pythonPublicKey = await importPublicKeyFromJwk(fromPython.pubJwk);
if (!await verifyPayload(pythonPublicKey, pythonPayload, fromPython.headers['X-BPC-Signature'])) {
  throw new Error('TypeScript rejected the Python P1363 signature');
}
const requestKey = await hashSecret(secret);
if (!await verifySecretHmac(
  requestKey,
  String(pythonPayload['nonce']),
  Number(pythonPayload['timestamp']),
  String(pythonPayload['secret_hmac']),
)) {
  throw new Error('TypeScript rejected the Python request HMAC');
}
if (await computeFingerprint(fromPython.pubJwk) !== fromPython.fingerprint) {
  throw new Error('Python and TypeScript public-key fingerprints differ');
}

const keypair = await generateKeypair();
const nonce = globalThis.crypto.randomUUID();
const timestamp = Date.now();
const bodyHash = `sha256:${b64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode('{}')))}`;
const derivedKey = await hashSecret(secret);
const payload = {
  body_hash: bodyHash,
  method: 'POST',
  nonce,
  pair_id: `pair_${randomUUID().replaceAll('-', '')}`,
  path: '/interop',
  secret_hmac: await hmacDerive(derivedKey, nonce + timestamp),
  timestamp,
  version: '1.0',
};
const signature = await signPayload(keypair.privateKey, payload);
const pythonVerifier = String.raw`
import base64, json, sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA, EllipticCurvePublicNumbers, SECP256R1
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA256

def dec(value):
    return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))

item = json.load(sys.stdin)
jwk = item["pubJwk"]
public_key = EllipticCurvePublicNumbers(
    int.from_bytes(dec(jwk["x"]), "big"),
    int.from_bytes(dec(jwk["y"]), "big"),
    SECP256R1(),
).public_key(default_backend())
raw = dec(item["signature"])
if len(raw) != 64:
    raise ValueError("TypeScript signature was not 64-byte P1363")
der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
public_key.verify(der, item["canonical"].encode(), ECDSA(SHA256()))
`;
const verifyResult = spawnSync('python', ['-c', pythonVerifier], {
  cwd: process.cwd(),
  encoding: 'utf8',
  env: environment,
  input: JSON.stringify({ pubJwk: keypair.pubJwk, signature, canonical: canonicalize(payload) }),
});
if (verifyResult.status !== 0) throw new Error(`Python rejected TypeScript signature: ${verifyResult.stderr}`);

console.log('Cross-language integration: PASS (P1363 signatures, HKDF/HMAC, fingerprint)');
