import { describe, it, expect } from 'vitest';
import { generateKeypair, signPayload, verifyPayload, computeFingerprint } from '../src/crypto.js';
import { canonicalize } from '../src/canonical.js';
import { hashSecret, hmacDerive, verifySecretHmac } from '../src/hmac.js';
import { b64url, b64urlDecode } from '../src/encoding.js';
import { generateNonce, NonceStore } from '../src/nonce.js';
import { validateSecret, hashSecretForStorage, verifyStoredSecret } from '../src/secret.js';
import {
  collectRuntimeMetadata,
  sanitizeCaptureValue,
  setKeyGenerationCaptureSink,
  type KeyGenerationCaptureEvent,
} from '../src/runtime-capture.js';

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

  it('emits opt-in key generation capture without exposing private key material', async () => {
    const events: KeyGenerationCaptureEvent[] = [];
    setKeyGenerationCaptureSink(event => events.push(event));

    try {
      const kp = await generateKeypair({
        runtimeMetadata: {
          tool: 'codex',
          model: 'gpt-5.5',
          sessionId: 'session-test',
        },
        captureDetails: {
          privateKey: 'must-not-leak',
          apiToken: 'must-not-leak',
        },
      });

      expect(events).toHaveLength(1);
      expect(events[0].event).toBe('bpc.keypair.generated');
      expect(events[0].keyFingerprint).toBe(kp.fingerprint);
      expect(events[0].runtime.model).toBe('gpt-5.5');

      const serialized = JSON.stringify(events[0]);
      expect(serialized).toContain(kp.fingerprint);
      expect(serialized).not.toContain('must-not-leak');
      expect(serialized).toContain('[REDACTED]');
    } finally {
      setKeyGenerationCaptureSink(undefined);
    }
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

describe('runtime capture', () => {
  it('collects Claude/Codex-style metadata from AI_RUNTIME env vars', () => {
    const previousModel = process.env['AI_RUNTIME_MODEL'];
    const previousSession = process.env['AI_RUNTIME_SESSION_ID'];
    process.env['AI_RUNTIME_MODEL'] = 'gpt-5.5';
    process.env['AI_RUNTIME_SESSION_ID'] = 'runtime-session-123';

    try {
      const runtime = collectRuntimeMetadata();
      expect(runtime.model).toBe('gpt-5.5');
      expect(runtime.sessionId).toBe('runtime-session-123');
      expect(runtime.capturedAt).toBeDefined();
    } finally {
      if (previousModel === undefined) delete process.env['AI_RUNTIME_MODEL'];
      else process.env['AI_RUNTIME_MODEL'] = previousModel;
      if (previousSession === undefined) delete process.env['AI_RUNTIME_SESSION_ID'];
      else process.env['AI_RUNTIME_SESSION_ID'] = previousSession;
    }
  });

  it('redacts recursively named secret/token/private fields', () => {
    const sanitized = sanitizeCaptureValue({
      ok: 'visible',
      nested: {
        sharedSecret: 'hidden',
        rawKey: 'hidden',
        authorization: 'hidden',
      },
    }) as Record<string, unknown>;

    const serialized = JSON.stringify(sanitized);
    expect(serialized).toContain('visible');
    expect(serialized).not.toContain('hidden');
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

  it('rejects HMAC when stored key is empty (BPC-01 fix — no fallback)', async () => {
    // v0.1.0 fallback has been removed: empty stored key MUST always fail.
    const validHmac = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmno';
    expect(await verifySecretHmac('', 'nonce', 123, validHmac)).toBe(false);
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
  // IL4-7 policy: min 16 chars, max 128 chars, 2+ special chars.

  it('accepts a valid IL4-7 compliant secret', () => {
    const result = validateSecret('ValidSecret1!@#$');
    expect(result.valid).toBe(true);
    expect(result.reason).toBeUndefined();
  });

  it('rejects too-short secret (< 16 chars)', () => {
    const result = validateSecret('Ab1!@');
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('at least');
  });

  it('rejects secret missing uppercase', () => {
    const result = validateSecret('myp@ss1!abc1234!!');
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('uppercase');
  });

  it('rejects secret missing lowercase', () => {
    const result = validateSecret('MYP@SS1!ABC1234!!');
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('lowercase');
  });

  it('rejects secret missing digit', () => {
    const result = validateSecret('MyP@ssssABCDEF!!');
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('digit');
  });

  it('rejects secret with only one special character', () => {
    // 16+ chars, has upper/lower/digit, but only ONE special char
    const result = validateSecret('MyPasss1abcDEF1!');
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('two special');
  });

  it('rejects secret exceeding max length (> 128 chars)', () => {
    // 130 chars total: 120 'A' + 'b' + '1' + '!@' + 7 more 'A' = 130
    const result = validateSecret('A'.repeat(126) + 'b1!@');
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
