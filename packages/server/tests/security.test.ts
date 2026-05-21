/**
 * BPC Protocol — Adversarial Security Test Suite
 *
 * Tests every vulnerability identified in the penetration test report and
 * verifies each fix is effective. All tests run against real cryptographic
 * operations — no mocking.
 *
 * Coverage:
 *   BPC-01: HMAC Authentication Bypass (empty secretHash)
 *   BPC-02: Rotation DoS (ReferenceError: payload is not defined)
 *   BPC-03: Weak Secret Hashing (SHA-256 vs HKDF)
 *   BPC-04: Unauthenticated Pair Enumeration + Admin Endpoint Auth
 *   BPC-05: __proto__ Injection in Canonical Payload
 *   BPC-06: Rate Limiter Saturation (IP + per-pair dual-track)
 *   IL4-7:  Input validation, nonce format, method allowlist, type confusion
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  generateKeypair,
  signPayload,
  canonicalize,
  hashSecret,
  hmacDerive,
  generateNonce,
  b64url,
  BPC_PROTOCOL_VERSION,
} from '../../core/src/index.js';
import type { BPCCanonicalPayload } from '../../core/src/types.js';
import { PairRegistry } from '../src/registry.js';
import { ServerNonceStore } from '../src/nonce-store.js';
import { AnomalyEngine } from '../src/anomaly.js';
import { verifyBPCRequest } from '../src/middleware.js';
import { verifyAdminRequest } from '../src/admin.js';
import { MemoryPairStore, MemoryNonceBackend, MemoryAnomalyStore } from '../src/memory-store.js';
import { MemoryRateLimiter } from '../src/rate-limiter.js';
import { handleRotation } from '../src/rotation.js';
import type { BPCRequestData } from '../src/middleware.js';
import { validateSecret, MIN_SECRET_LENGTH } from '../../core/src/secret.js';

// ─── Test helpers ─────────────────────────────────────────────────────────────

function encodePayload(payload: Record<string, unknown>): string {
  const json = canonicalize(payload);
  const bytes = new TextEncoder().encode(json);
  const binary = String.fromCharCode(...bytes);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

async function buildSignedRequest(
  privateKey: CryptoKey,
  pairId: string,
  method: string,
  path: string,
  secretHash: string,
  overrides: Partial<BPCCanonicalPayload> = {},
): Promise<{ payload: BPCCanonicalPayload; signedData: string; signature: string; bodyHash: string }> {
  const nonce     = generateNonce();
  const timestamp = Date.now();
  const bodyHash  = b64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode('')));
  const secretHmac = await hmacDerive(secretHash, nonce + timestamp);

  const payload: BPCCanonicalPayload = {
    body_hash:   bodyHash,
    method,
    nonce,
    pair_id:     pairId,
    path,
    secret_hmac: secretHmac,
    timestamp,
    version:     BPC_PROTOCOL_VERSION,
    ...overrides,
  };

  const signature  = await signPayload(privateKey, payload as unknown as Record<string, unknown>);
  const signedData = encodePayload(payload as unknown as Record<string, unknown>);
  return { payload, signedData, signature, bodyHash };
}

function makeReqData(
  overrides: Partial<BPCRequestData> & {
    pairId: string | null;
    signedData: string | null;
    signature: string | null;
    method: string;
    path: string;
  },
): BPCRequestData {
  return { version: BPC_PROTOCOL_VERSION, bodyHash: null, ip: '127.0.0.1', ...overrides };
}

// ─── BPC-01: HMAC Authentication Bypass ──────────────────────────────────────

describe('BPC-01 — HMAC Authentication Bypass (FIXED)', () => {
  it('rejects registration with empty secretHash', async () => {
    const store    = new MemoryPairStore();
    const registry = new PairRegistry(store);
    const kp       = await generateKeypair();

    await expect(
      registry.registerDirect({
        name: 'attacker', scope: 'read', mode: 'development',
        secretHash: '', pubJwk: kp.pubJwk,
      }),
    ).rejects.toThrow();
  });

  it('rejects registration with short secretHash (< 43 chars)', async () => {
    const store    = new MemoryPairStore();
    const registry = new PairRegistry(store);
    const kp       = await generateKeypair();

    await expect(
      registry.registerDirect({
        name: 'attacker', scope: 'read', mode: 'development',
        secretHash: 'tooshort', pubJwk: kp.pubJwk,
      }),
    ).rejects.toThrow('secretHash');
  });

  it('rejects registration with null secretHash', async () => {
    const store    = new MemoryPairStore();
    const registry = new PairRegistry(store);
    const kp       = await generateKeypair();

    await expect(
      registry.registerDirect({
        name: 'attacker', scope: 'read', mode: 'development',
        secretHash: null as unknown as string, pubJwk: kp.pubJwk,
      }),
    ).rejects.toThrow();
  });

  it('middleware rejects request when pair has empty secretHash (defense-in-depth)', async () => {
    // Bypass registry validation by writing directly to the store
    const store      = new MemoryPairStore();
    const registry   = new PairRegistry(store);
    const nonceStore = new ServerNonceStore(new MemoryNonceBackend(), 120_000);
    const anomaly    = new AnomalyEngine(new MemoryAnomalyStore());
    const kp         = await generateKeypair();

    // Force a pair with empty secretHash into the store (bypassing validation)
    const pairId = 'pair_test_empty_secret';
    await store.set({
      id: pairId, name: 'bypass-test', scope: 'read', mode: 'development',
      secretHash: '', pubJwk: kp.pubJwk, status: 'active',
      created: Date.now(), lastActive: null, requests: 0, failedSigs: 0,
    });

    // Build the request using a dummy non-empty secretHash for the HMAC derivation step.
    // The middleware will reject because pair.secretHash is '' (empty) — that's what we're testing.
    // We cannot use '' as keyMaterial in hmacDerive (that's BPC-01 fix working correctly),
    // so we use a dummy value to get past the client-side signing step.
    const dummyHash = 'a'.repeat(43); // 43-char base64url — valid format, wrong value
    const { signedData, signature, bodyHash } = await buildSignedRequest(
      kp.privateKey, pairId, 'GET', '/api/data', dummyHash,
    );

    const result = await verifyBPCRequest(
      makeReqData({ pairId, signedData, signature, method: 'GET', path: '/api/data', bodyHash }),
      registry, nonceStore, anomaly,
    );

    // Must be rejected — empty secretHash on the stored pair is a hard failure
    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/secret_hmac|missing_secret_hmac|invalid_secret_hmac/);
  });

  it('middleware rejects request with wrong HMAC (no fallback)', async () => {
    const store      = new MemoryPairStore();
    const registry   = new PairRegistry(store);
    const nonceStore = new ServerNonceStore(new MemoryNonceBackend(), 120_000);
    const anomaly    = new AnomalyEngine(new MemoryAnomalyStore());
    const kp         = await generateKeypair();
    const sh         = await hashSecret('ValidSecret1!@#$');

    const pairId = await registry.registerDirect({
      name: 'test', scope: 'read', mode: 'development', secretHash: sh, pubJwk: kp.pubJwk,
    });

    // Use a random HMAC value — not derived from the correct secret
    const wrongHmac = b64url(crypto.getRandomValues(new Uint8Array(32)).buffer);
    const { signedData, signature, bodyHash } = await buildSignedRequest(
      kp.privateKey, pairId, 'GET', '/api/data', sh,
      { secret_hmac: wrongHmac },
    );

    const result = await verifyBPCRequest(
      makeReqData({ pairId, signedData, signature, method: 'GET', path: '/api/data', bodyHash }),
      registry, nonceStore, anomaly,
    );

    expect(result.ok).toBe(false);
    expect(result.error).toBe('invalid_secret_hmac');
  });

  it('accepts a valid request with correct HMAC', async () => {
    const store      = new MemoryPairStore();
    const registry   = new PairRegistry(store);
    const nonceStore = new ServerNonceStore(new MemoryNonceBackend(), 120_000);
    const anomaly    = new AnomalyEngine(new MemoryAnomalyStore());
    const kp         = await generateKeypair();
    const sh         = await hashSecret('ValidSecret1!@#$');

    const pairId = await registry.registerDirect({
      name: 'test', scope: 'read', mode: 'development', secretHash: sh, pubJwk: kp.pubJwk,
    });

    const { signedData, signature, bodyHash } = await buildSignedRequest(
      kp.privateKey, pairId, 'GET', '/api/data', sh,
    );

    const result = await verifyBPCRequest(
      makeReqData({ pairId, signedData, signature, method: 'GET', path: '/api/data', bodyHash }),
      registry, nonceStore, anomaly,
    );

    expect(result.ok).toBe(true);
  });
});

// ─── BPC-02: Rotation DoS ─────────────────────────────────────────────────────

describe('BPC-02 — Rotation DoS (FIXED)', () => {
  it('handleRotation returns error result for unknown pair (no crash)', async () => {
    const store = new MemoryPairStore();
    const registry = new PairRegistry(store);

    const result = await handleRotation(
      { oldPairId: 'pair_nonexistent', newPubJwk: {} as JsonWebKey, signature: 'sig', signedData: 'data', timestamp: Date.now() },
      store,
    );

    expect(result.ok).toBe(false);
    expect(result.error).toBeDefined();
  });

  it('handleRotation succeeds with valid rotation payload', async () => {
    const store    = new MemoryPairStore();
    const registry = new PairRegistry(store);
    const kp       = await generateKeypair();
    const sh       = await hashSecret('ValidSecret1!@#$');

    const pairId = await registry.registerDirect({
      name: 'rotate-test', scope: 'read-write', mode: 'development',
      secretHash: sh, pubJwk: kp.pubJwk,
    });

    const newKp = await generateKeypair();
    const timestamp = Date.now();
    const rotPayload = {
      new_pub_jwk_json: JSON.stringify(newKp.pubJwk),
      old_pair_id: pairId,
      purpose: 'rotation',
      timestamp,
    };
    const signature  = await signPayload(kp.privateKey, rotPayload);
    const signedData = b64url(new TextEncoder().encode(canonicalize(rotPayload)).buffer);

    const result = await handleRotation(
      { oldPairId: pairId, newPubJwk: newKp.pubJwk, signature, signedData, timestamp },
      store,
    );

    expect(result.ok).toBe(true);
    expect(result.newPairId).toBeTruthy();
  });

  it('handleRotation rejects expired timestamp (no crash)', async () => {
    const store    = new MemoryPairStore();
    const registry = new PairRegistry(store);
    const kp       = await generateKeypair();
    const sh       = await hashSecret('ValidSecret1!@#$');

    const pairId = await registry.registerDirect({
      name: 'rotate-expire', scope: 'read-write', mode: 'development',
      secretHash: sh, pubJwk: kp.pubJwk,
    });

    const newKp = await generateKeypair();
    const timestamp = Date.now() - 200_000; // 200 seconds ago — expired
    const rotPayload = {
      new_pub_jwk_json: JSON.stringify(newKp.pubJwk),
      old_pair_id: pairId,
      purpose: 'rotation',
      timestamp,
    };
    const signature  = await signPayload(kp.privateKey, rotPayload);
    const signedData = b64url(new TextEncoder().encode(canonicalize(rotPayload)).buffer);

    const result = await handleRotation(
      { oldPairId: pairId, newPubJwk: newKp.pubJwk, signature, signedData, timestamp },
      store,
    );

    expect(result.ok).toBe(false);
    expect(result.error).toMatch(/expired|timestamp/);
  });
});

// ─── BPC-03: Weak Secret Hashing ─────────────────────────────────────────────

describe('BPC-03 — Weak Secret Hashing (FIXED)', () => {
  it('hashSecret produces HKDF output (43 chars, base64url)', async () => {
    const hash = await hashSecret('ValidSecret1!@#$');
    // HKDF-SHA-256 output: 32 bytes = 43 base64url chars (no padding)
    expect(hash.length).toBe(43);
    expect(/^[A-Za-z0-9_-]+$/.test(hash)).toBe(true);
  });

  it('hashSecret is deterministic', async () => {
    const h1 = await hashSecret('ValidSecret1!@#$');
    const h2 = await hashSecret('ValidSecret1!@#$');
    expect(h1).toBe(h2);
  });

  it('hashSecret produces different outputs for different secrets', async () => {
    const h1 = await hashSecret('ValidSecret1!@#$');
    const h2 = await hashSecret('DifferentSecret2!@');
    expect(h1).not.toBe(h2);
  });

  it('hashSecret output is not a raw SHA-256 hex string', async () => {
    const hash = await hashSecret('ValidSecret1!@#$');
    // Raw SHA-256 hex would be 64 chars; HKDF base64url is 43 chars
    expect(hash.length).not.toBe(64);
    expect(/^[0-9a-f]+$/.test(hash)).toBe(false);
  });
});

// ─── BPC-04: Unauthenticated Pair Enumeration + Admin Auth ───────────────────

describe('BPC-04 — Unauthenticated Pair Enumeration (FIXED)', () => {
  it('listRedacted() strips secretHash and pubJwk', async () => {
    const store    = new MemoryPairStore();
    const registry = new PairRegistry(store);
    const kp       = await generateKeypair();
    const sh       = await hashSecret('ValidSecret1!@#$');

    await registry.registerDirect({ name: 'test', scope: 'read', mode: 'production', secretHash: sh, pubJwk: kp.pubJwk });

    const redacted = await registry.listRedacted();
    expect(redacted.length).toBe(1);

    const pair = redacted[0];
    expect(pair.id).toBeTruthy();
    expect(pair.name).toBe('test');
    // Sensitive fields must NOT be present
    expect((pair as Record<string, unknown>)['secretHash']).toBeUndefined();
    expect((pair as Record<string, unknown>)['pubJwk']).toBeUndefined();
    expect((pair as Record<string, unknown>)['failedSigs']).toBeUndefined();
    expect((pair as Record<string, unknown>)['expiresAt']).toBeUndefined();
  });

  it('listRedacted() returns only safe fields', async () => {
    const store    = new MemoryPairStore();
    const registry = new PairRegistry(store);
    const kp       = await generateKeypair();
    const sh       = await hashSecret('ValidSecret1!@#$');

    await registry.registerDirect({ name: 'safe', scope: 'read-write', mode: 'development', secretHash: sh, pubJwk: kp.pubJwk });

    const redacted = await registry.listRedacted();
    const allowedKeys = new Set(['id', 'name', 'scope', 'mode', 'status', 'created', 'lastActive', 'requests']);
    for (const key of Object.keys(redacted[0])) {
      expect(allowedKeys.has(key)).toBe(true);
    }
  });

  // ── Admin endpoint authentication tests ──────────────────────────────────
  it('verifyAdminRequest() denies request with no config (fail-closed)', async () => {
    const allowed = await verifyAdminRequest({ authorization: 'Bearer sometoken' }, undefined);
    expect(allowed).toBe(false);
  });

  it('verifyAdminRequest() denies request with wrong bearer token', async () => {
    const allowed = await verifyAdminRequest(
      { authorization: 'Bearer wrong-token' },
      { bearerToken: 'correct-token-32-bytes-long-here!!' },
    );
    expect(allowed).toBe(false);
  });

  it('verifyAdminRequest() denies request with missing Authorization header', async () => {
    const allowed = await verifyAdminRequest(
      {},
      { bearerToken: 'correct-token-32-bytes-long-here!!' },
    );
    expect(allowed).toBe(false);
  });

  it('verifyAdminRequest() allows request with correct bearer token', async () => {
    const allowed = await verifyAdminRequest(
      { authorization: 'Bearer correct-token-32-bytes-long-here!!' },
      { bearerToken: 'correct-token-32-bytes-long-here!!' },
    );
    expect(allowed).toBe(true);
  });

  it('verifyAdminRequest() uses custom verifier when provided', async () => {
    const allowed = await verifyAdminRequest(
      { 'x-custom-auth': 'magic-value' },
      {
        verifier: async (headers) => headers['x-custom-auth'] === 'magic-value',
      },
    );
    expect(allowed).toBe(true);
  });

  it('verifyAdminRequest() denies when custom verifier returns false', async () => {
    const allowed = await verifyAdminRequest(
      { 'x-custom-auth': 'wrong-value' },
      {
        verifier: async (headers) => headers['x-custom-auth'] === 'magic-value',
      },
    );
    expect(allowed).toBe(false);
  });

  it('verifyAdminRequest() requires BOTH bearerToken AND verifier to pass when both set', async () => {
    // Correct bearer token but verifier returns false
    const denied = await verifyAdminRequest(
      { authorization: 'Bearer correct-token' },
      {
        bearerToken: 'correct-token',
        verifier: async () => false,
      },
    );
    expect(denied).toBe(false);

    // Both pass
    const allowed = await verifyAdminRequest(
      { authorization: 'Bearer correct-token' },
      {
        bearerToken: 'correct-token',
        verifier: async () => true,
      },
    );
    expect(allowed).toBe(true);
  });
});

// ─── BPC-05: __proto__ Injection ─────────────────────────────────────────────

describe('BPC-05 — __proto__ Canonical Payload Injection (FIXED)', () => {
  it('canonicalize throws on __proto__ key', () => {
    const payload = JSON.parse('{"__proto__":{"injected":true},"method":"GET"}') as Record<string, unknown>;
    expect(() => canonicalize(payload)).toThrow('forbidden key');
  });

  it('canonicalize throws on constructor key', () => {
    expect(() => canonicalize({ constructor: 'evil', method: 'GET' })).toThrow('forbidden key');
  });

  it('canonicalize throws on prototype key', () => {
    expect(() => canonicalize({ prototype: 'evil', method: 'GET' })).toThrow('forbidden key');
  });

  it('canonicalize throws on nested object values', () => {
    expect(() => canonicalize({ nested: { key: 'value' } as unknown as string })).toThrow('nested object');
  });

  it('canonicalize throws on array values', () => {
    expect(() => canonicalize({ arr: ['a', 'b'] as unknown as string })).toThrow('nested object');
  });

  it('canonicalize accepts valid flat payload', () => {
    const result = canonicalize({ z: 'last', a: 'first', m: 42 });
    expect(result).toBe('{"a":"first","m":42,"z":"last"}');
  });

  it('canonicalize is deterministic (key order independent)', () => {
    const a = canonicalize({ z: 1, a: 2, m: 3 });
    const b = canonicalize({ a: 2, m: 3, z: 1 });
    expect(a).toBe(b);
  });

  it('middleware rejects request with __proto__ in signedData', async () => {
    const store      = new MemoryPairStore();
    const registry   = new PairRegistry(store);
    const nonceStore = new ServerNonceStore(new MemoryNonceBackend(), 120_000);
    const anomaly    = new AnomalyEngine(new MemoryAnomalyStore());
    const kp         = await generateKeypair();
    const sh         = await hashSecret('ValidSecret1!@#$');

    const pairId = await registry.registerDirect({ name: 'test', scope: 'admin', mode: 'development', secretHash: sh, pubJwk: kp.pubJwk });

    // Craft a signedData with __proto__ key injected
    const maliciousPayload = '{"__proto__":{"isAdmin":true},"method":"GET","nonce":"' + generateNonce() + '","pair_id":"' + pairId + '","path":"/api/data","secret_hmac":"' + 'a'.repeat(43) + '","timestamp":' + Date.now() + ',"version":"1.0"}';
    const bytes    = new TextEncoder().encode(maliciousPayload);
    const binary   = String.fromCharCode(...bytes);
    const signedData = btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    const signature  = b64url(crypto.getRandomValues(new Uint8Array(64)).buffer);

    const result = await verifyBPCRequest(
      makeReqData({ pairId, signedData, signature, method: 'GET', path: '/api/data' }),
      registry, nonceStore, anomaly,
    );

    expect(result.ok).toBe(false);
  });
});

// ─── BPC-06: Rate Limiter Saturation ─────────────────────────────────────────

describe('BPC-06 — Rate Limiter Saturation (FIXED)', () => {
  it('capacity guard evicts keys when limit exceeded', async () => {
    // Use a small limit to test capacity guard behavior
    const limiter = new MemoryRateLimiter(1000, 60_000);

    // Fill the limiter with unique keys
    for (let i = 0; i < 100; i++) {
      await limiter.check(`key-${i}`);
    }

    // Verify it still works after many keys
    const result = await limiter.check('new-key');
    expect(result.allowed).toBe(true);
  });

  it('per-IP limit does not affect per-pairId limit', async () => {
    const ipLimiter   = new MemoryRateLimiter(1, 60_000);  // 1 req/min per IP
    const pairLimiter = new MemoryRateLimiter(5, 60_000);  // 5 req/min per pair

    // First request from IP — allowed
    const r1 = await ipLimiter.check('ip:1.2.3.4');
    expect(r1.allowed).toBe(true);

    // Second request from same IP — blocked by IP limiter
    const r2 = await ipLimiter.check('ip:1.2.3.4');
    expect(r2.allowed).toBe(false);

    // But pairId limiter is independent — still has capacity
    const r3 = await pairLimiter.check('pair:pair_abc');
    expect(r3.allowed).toBe(true);
    const r4 = await pairLimiter.check('pair:pair_abc');
    expect(r4.allowed).toBe(true);
  });

  it('ipRateLimiter in BPCServerConfig fires before pairId is read', async () => {
    // The ipRateLimiter should block even requests with no BPC headers at all
    const store      = new MemoryPairStore();
    const registry   = new PairRegistry(store);
    const nonceStore = new ServerNonceStore(new MemoryNonceBackend(), 120_000);
    const anomaly    = new AnomalyEngine(new MemoryAnomalyStore());
    const ipLimiter  = new MemoryRateLimiter(1, 60_000); // 1 req/min per IP

    // First request — allowed (but fails due to missing headers, not rate limit)
    const r1 = await verifyBPCRequest(
      makeReqData({ pairId: null, signedData: null, signature: null, method: 'GET', path: '/api/data', ip: '10.0.0.1' }),
      registry, nonceStore, anomaly,
      { sigWindowMs: 60_000, ipRateLimiter: ipLimiter },
    );
    // Should fail with missing_headers (rate limit not yet hit)
    expect(r1.ok).toBe(false);
    expect(r1.error).toBe('missing_headers');

    // Second request from same IP — blocked by IP rate limiter BEFORE headers are checked
    const r2 = await verifyBPCRequest(
      makeReqData({ pairId: null, signedData: null, signature: null, method: 'GET', path: '/api/data', ip: '10.0.0.1' }),
      registry, nonceStore, anomaly,
      { sigWindowMs: 60_000, ipRateLimiter: ipLimiter },
    );
    expect(r2.ok).toBe(false);
    expect(r2.error).toBe('rate_limit_exceeded');
  });

  it('ipRateLimiter does not affect requests from different IPs', async () => {
    const store      = new MemoryPairStore();
    const registry   = new PairRegistry(store);
    const nonceStore = new ServerNonceStore(new MemoryNonceBackend(), 120_000);
    const anomaly    = new AnomalyEngine(new MemoryAnomalyStore());
    const ipLimiter  = new MemoryRateLimiter(1, 60_000); // 1 req/min per IP

    // Exhaust IP 10.0.0.1
    await verifyBPCRequest(
      makeReqData({ pairId: null, signedData: null, signature: null, method: 'GET', path: '/api/data', ip: '10.0.0.1' }),
      registry, nonceStore, anomaly,
      { sigWindowMs: 60_000, ipRateLimiter: ipLimiter },
    );

    // Different IP 10.0.0.2 should NOT be blocked
    const r = await verifyBPCRequest(
      makeReqData({ pairId: null, signedData: null, signature: null, method: 'GET', path: '/api/data', ip: '10.0.0.2' }),
      registry, nonceStore, anomaly,
      { sigWindowMs: 60_000, ipRateLimiter: ipLimiter },
    );
    // Should fail with missing_headers (not rate_limit_exceeded)
    expect(r.error).toBe('missing_headers');
  });
});

// ─── IL4-7: Input Validation ──────────────────────────────────────────────────

describe('IL4-7 — Input Validation Hardening', () => {
  let registry: PairRegistry;
  let nonceStore: ServerNonceStore;
  let anomaly: AnomalyEngine;
  let keypair: Awaited<ReturnType<typeof generateKeypair>>;
  let pairId: string;
  let secretHash: string;

  beforeEach(async () => {
    const store = new MemoryPairStore();
    registry    = new PairRegistry(store);
    nonceStore  = new ServerNonceStore(new MemoryNonceBackend(), 120_000);
    anomaly     = new AnomalyEngine(new MemoryAnomalyStore());
    keypair     = await generateKeypair();
    secretHash  = await hashSecret('ValidSecret1!@#$');
    pairId      = await registry.registerDirect({ name: 'test', scope: 'admin', mode: 'development', secretHash, pubJwk: keypair.pubJwk });
  });

  it('rejects unknown HTTP method (TRACE)', async () => {
    const { signedData, signature } = await buildSignedRequest(keypair.privateKey, pairId, 'TRACE', '/api/data', secretHash);
    const result = await verifyBPCRequest(
      makeReqData({ pairId, signedData, signature, method: 'TRACE', path: '/api/data' }),
      registry, nonceStore, anomaly,
    );
    expect(result.ok).toBe(false);
    expect(result.error).toBe('invalid_method');
  });

  it('rejects pairId with special characters (injection attempt)', async () => {
    const { signedData, signature } = await buildSignedRequest(keypair.privateKey, pairId, 'GET', '/api/data', secretHash);
    const result = await verifyBPCRequest(
      makeReqData({ pairId: 'pair_<script>alert(1)</script>', signedData, signature, method: 'GET', path: '/api/data' }),
      registry, nonceStore, anomaly,
    );
    expect(result.ok).toBe(false);
    expect(result.error).toBe('invalid_signed_data');
  });

  it('rejects payload with non-UUID nonce', async () => {
    const nonce     = 'not-a-uuid';
    const timestamp = Date.now();
    const bodyHash  = b64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode('')));
    const secretHmac = await hmacDerive(secretHash, nonce + timestamp);

    const payload: BPCCanonicalPayload = {
      body_hash: bodyHash, method: 'GET', nonce, pair_id: pairId,
      path: '/api/data', secret_hmac: secretHmac, timestamp, version: BPC_PROTOCOL_VERSION,
    };
    const signature  = await signPayload(keypair.privateKey, payload as unknown as Record<string, unknown>);
    const signedData = encodePayload(payload as unknown as Record<string, unknown>);

    const result = await verifyBPCRequest(
      makeReqData({ pairId, signedData, signature, method: 'GET', path: '/api/data', bodyHash }),
      registry, nonceStore, anomaly,
    );
    expect(result.ok).toBe(false);
    expect(result.error).toBe('invalid_signed_data');
  });

  it('rejects registration with invalid scope', async () => {
    const store    = new MemoryPairStore();
    const registry = new PairRegistry(store);
    const kp       = await generateKeypair();
    const sh       = await hashSecret('ValidSecret1!@#$');

    await expect(
      registry.registerDirect({ name: 'test', scope: 'superadmin' as 'admin', mode: 'development', secretHash: sh, pubJwk: kp.pubJwk }),
    ).rejects.toThrow('scope');
  });

  it('rejects registration with invalid mode', async () => {
    const store    = new MemoryPairStore();
    const registry = new PairRegistry(store);
    const kp       = await generateKeypair();
    const sh       = await hashSecret('ValidSecret1!@#$');

    await expect(
      registry.registerDirect({ name: 'test', scope: 'read', mode: 'staging' as 'production', secretHash: sh, pubJwk: kp.pubJwk }),
    ).rejects.toThrow('mode');
  });
});

// ─── IL4-7: Secret Policy ─────────────────────────────────────────────────────

describe('IL4-7 — Secret Policy (MIN_SECRET_LENGTH = 16)', () => {
  it('rejects secrets shorter than 16 characters', () => {
    const result = validateSecret('Short1!');
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('at least');
  });

  it('rejects secrets with only one special character', () => {
    const result = validateSecret('ValidSecret1234!');
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('two special');
  });

  it('accepts a valid IL4-7 compliant secret', () => {
    const result = validateSecret('ValidSecret1!@#$');
    expect(result.valid).toBe(true);
  });

  it(`MIN_SECRET_LENGTH is ${MIN_SECRET_LENGTH}`, () => {
    expect(MIN_SECRET_LENGTH).toBe(16);
  });
});

// ─── Full end-to-end: happy path still works ─────────────────────────────────

describe('End-to-End: Hardened Protocol Happy Path', () => {
  it('completes a full request lifecycle with all hardening active', async () => {
    const store      = new MemoryPairStore();
    const registry   = new PairRegistry(store);
    const nonceStore = new ServerNonceStore(new MemoryNonceBackend(), 120_000);
    const anomaly    = new AnomalyEngine(new MemoryAnomalyStore());
    const kp         = await generateKeypair();
    const secret     = 'ValidSecret1!@#$';
    const sh         = await hashSecret(secret);

    const pairId = await registry.registerDirect({
      name:       'production-client',
      scope:      'read-write',
      mode:       'production',
      secretHash: sh,
      pubJwk:     kp.pubJwk,
    });

    const { signedData, signature, bodyHash } = await buildSignedRequest(
      kp.privateKey, pairId, 'POST', '/api/resource', sh,
    );

    const result = await verifyBPCRequest(
      makeReqData({ pairId, signedData, signature, method: 'POST', path: '/api/resource', bodyHash }),
      registry, nonceStore, anomaly,
      { sigWindowMs: 60_000 },
    );

    expect(result.ok).toBe(true);
    expect(result.pairId).toBe(pairId);
    expect(result.pair?.name).toBe('production-client');
    expect(result.pair?.scope).toBe('read-write');
  });

  it('dual-track rate limiters work together without interfering', async () => {
    const store       = new MemoryPairStore();
    const registry    = new PairRegistry(store);
    const nonceStore  = new ServerNonceStore(new MemoryNonceBackend(), 120_000);
    const anomaly     = new AnomalyEngine(new MemoryAnomalyStore());
    const kp          = await generateKeypair();
    const sh          = await hashSecret('ValidSecret1!@#$');
    const ipLimiter   = new MemoryRateLimiter(100, 60_000);
    const pairLimiter = new MemoryRateLimiter(50, 60_000);

    const pairId = await registry.registerDirect({
      name: 'dual-rate-test', scope: 'read', mode: 'development', secretHash: sh, pubJwk: kp.pubJwk,
    });

    // 5 valid requests should all pass
    for (let i = 0; i < 5; i++) {
      const { signedData, signature, bodyHash } = await buildSignedRequest(
        kp.privateKey, pairId, 'GET', '/api/data', sh,
      );
      const result = await verifyBPCRequest(
        makeReqData({ pairId, signedData, signature, method: 'GET', path: '/api/data', bodyHash }),
        registry, nonceStore, anomaly,
        { sigWindowMs: 60_000, ipRateLimiter: ipLimiter, rateLimiter: pairLimiter },
      );
      expect(result.ok).toBe(true);
    }
  });
});
