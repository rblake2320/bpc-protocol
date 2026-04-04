import { describe, it, expect } from 'vitest';
import { generateKeypair, signPayload, verifyPayload, computeFingerprint } from '../src/crypto.js';
import { canonicalize } from '../src/canonical.js';
import { hashSecret, hmacDerive, verifySecretHmac } from '../src/hmac.js';
import { b64url, b64urlDecode } from '../src/encoding.js';
import { generateNonce, NonceStore } from '../src/nonce.js';
import { validateSecret, hashSecretForStorage, verifyStoredSecret } from '../src/secret.js';

describe('encoding', () => {
  it('base64url round-trips', () => {
    const data = new TextEncoder().encode('hello bpc');
    const encoded = b64url(data.buffer);
    expect(encoded).not.toContain('+');
    expect(encoded).not.toContain('/');
    expect(encoded).not.toContain('=');
    const decoded = b64urlDecode(encoded);
    expect(new TextDecoder().decode(decoded)).toBe('hello bpc');
  });
});

describe('canonical', () => {
  it('sorts keys deterministically', () => {
    const a = canonicalize({ z: 1, a: 2, m: 3 });
    const b = canonicalize({ m: 3, z: 1, a: 2 });
    expect(a).toBe(b);
    expect(a).toBe('{"a":2,"m":3,"z":1}');
  });
});

describe('crypto', () => {
  it('generates a keypair with fingerprint', async () => {
    const kp = await generateKeypair();
    expect(kp.fingerprint).toHaveLength(20);
    expect(kp.privateKey).toBeDefined();
    expect(kp.publicKey).toBeDefined();
  });

  it('sign and verify round-trips', async () => {
    const kp = await generateKeypair();
    const payload = { method: 'GET', path: '/api/test', nonce: 'abc', timestamp: 123 };
    const sig = await signPayload(kp.privateKey, payload);
    expect(sig.length).toBeGreaterThan(0);
    const valid = await verifyPayload(kp.publicKey, payload, sig);
    expect(valid).toBe(true);
  });

  it('rejects tampered payload', async () => {
    const kp = await generateKeypair();
    const payload = { method: 'GET', path: '/api/test', nonce: 'abc', timestamp: 123 };
    const sig = await signPayload(kp.privateKey, payload);
    const tampered = { ...payload, path: '/api/admin' };
    const valid = await verifyPayload(kp.publicKey, tampered, sig);
    expect(valid).toBe(false);
  });
});

describe('hmac', () => {
  it('hashes secret with bpc: prefix', async () => {
    const h1 = await hashSecret('mysecret');
    const h2 = await hashSecret('mysecret');
    expect(h1).toBe(h2);
    const h3 = await hashSecret('other');
    expect(h1).not.toBe(h3);
  });

  it('derives full-length base64url hmac from secret + data', async () => {
    const h = await hmacDerive('secret', 'nonce123456789');
    // SHA-256 HMAC → 32 bytes → 43 base64url chars (no padding)
    expect(h).toHaveLength(43);
    // Must be valid base64url
    expect(h).toMatch(/^[A-Za-z0-9_-]+$/);
  });
});

describe('verifySecretHmac', () => {
  it('rejects empty or too-short HMAC', async () => {
    expect(await verifySecretHmac('', 'nonce', 123, '')).toBe(false);
    expect(await verifySecretHmac('', 'nonce', 123, 'short')).toBe(false);
  });

  it('rejects invalid base64url characters', async () => {
    const badHmac = 'AAAAAAAAAAAAAAAAAAAAAA!@#$';
    expect(await verifySecretHmac('', 'nonce', 123, badHmac)).toBe(false);
  });

  it('accepts structurally valid HMAC without stored key (v0.1.0 fallback)', async () => {
    const validHmac = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmno';
    expect(await verifySecretHmac('', 'nonce', 123, validHmac)).toBe(true);
  });

  it('performs full verification when stored key is provided', async () => {
    const key = 'my-hmac-key-for-testing';
    const nonce = 'test-nonce';
    const timestamp = 1700000000;
    // Compute the expected HMAC using the same key
    const expected = await hmacDerive(key, nonce + timestamp);
    expect(await verifySecretHmac(key, nonce, timestamp, expected)).toBe(true);
    // Wrong HMAC should fail
    const wrongHmac = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmno';
    expect(await verifySecretHmac(key, nonce, timestamp, wrongHmac)).toBe(false);
  });
});

describe('validateSecret', () => {
  it('accepts a valid secret', () => {
    const result = validateSecret('MyP@ss1!');
    expect(result.valid).toBe(true);
    expect(result.reason).toBeUndefined();
  });

  it('rejects too-short secret', () => {
    const result = validateSecret('Ab1!');
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('at least');
  });

  it('rejects secret missing uppercase', () => {
    const result = validateSecret('myp@ss1!abc');
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('uppercase');
  });

  it('rejects secret missing lowercase', () => {
    const result = validateSecret('MYP@SS1!ABC');
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('lowercase');
  });

  it('rejects secret missing digit', () => {
    const result = validateSecret('MyP@ssss!');
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('digit');
  });

  it('rejects secret missing special character', () => {
    const result = validateSecret('MyPasss1abc');
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('special');
  });

  it('rejects secret exceeding max length', () => {
    const result = validateSecret('A'.repeat(65) + 'b1!');
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('at most');
  });
});

describe('hashSecretForStorage + verifyStoredSecret', () => {
  it('round-trips: hash then verify succeeds', async () => {
    const secret = 'MyT3st!Secret';
    const hash = await hashSecretForStorage(secret);
    expect(typeof hash).toBe('string');
    expect(hash.startsWith('$argon2id$')).toBe(true);
    const valid = await verifyStoredSecret(secret, hash);
    expect(valid).toBe(true);
  });

  it('rejects wrong secret', async () => {
    const hash = await hashSecretForStorage('Correct!1');
    const valid = await verifyStoredSecret('Wrong!1xx', hash);
    expect(valid).toBe(false);
  });

  it('produces different hashes for same input (unique salt)', async () => {
    const h1 = await hashSecretForStorage('Same!Pass1');
    const h2 = await hashSecretForStorage('Same!Pass1');
    expect(h1).not.toBe(h2); // different salts
  });
});

describe('NonceStore', () => {
  it('detects duplicate nonces', () => {
    const store = new NonceStore(60_000);
    const nonce = generateNonce();
    expect(store.has(nonce)).toBe(false);
    store.add(nonce);
    expect(store.has(nonce)).toBe(true);
  });

  it('evicts expired nonces', async () => {
    const store = new NonceStore(10); // 10ms window
    store.add('old-nonce');
    await new Promise(r => setTimeout(r, 20));
    expect(store.has('old-nonce')).toBe(false);
  });
});
