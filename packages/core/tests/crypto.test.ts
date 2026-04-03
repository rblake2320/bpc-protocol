import { describe, it, expect } from 'vitest';
import { generateKeypair, signPayload, verifyPayload, computeFingerprint } from '../src/crypto.js';
import { canonicalize } from '../src/canonical.js';
import { hashSecret, hmacDerive } from '../src/hmac.js';
import { b64url, b64urlDecode } from '../src/encoding.js';
import { generateNonce, NonceStore } from '../src/nonce.js';

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

  it('derives hmac from secret + data', async () => {
    const h = await hmacDerive('secret', 'nonce123456789');
    expect(h).toHaveLength(16);
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
