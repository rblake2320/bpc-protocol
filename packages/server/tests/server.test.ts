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
import { MemoryPairStore, MemoryNonceBackend, MemoryAnomalyStore } from '../src/memory-store.js';
import { MemoryRateLimiter } from '../src/rate-limiter.js';
import type { BPCRequestData } from '../src/middleware.js';

// --- Test helpers ---

function encodePayload(payload: Record<string, unknown>): string {
  const json = canonicalize(payload);
  // btoa expects binary string, TextEncoder gives us the bytes
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
): Promise<{ payload: BPCCanonicalPayload; signedData: string; signature: string }> {
  const nonce = generateNonce();
  const timestamp = Date.now();
  const bodyHash = b64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode('')));
  const secretHmac = await hmacDerive(secretHash, nonce + timestamp);

  const payload: BPCCanonicalPayload = {
    body_hash: bodyHash,
    method,
    nonce,
    pair_id: pairId,
    path,
    secret_hmac: secretHmac,
    timestamp,
    version: BPC_PROTOCOL_VERSION,
  };

  const signature = await signPayload(privateKey, payload as unknown as Record<string, unknown>);
  const signedData = encodePayload(payload as unknown as Record<string, unknown>);

  return { payload, signedData, signature };
}

function makeReqData(overrides: Partial<BPCRequestData> & { pairId: string | null; signedData: string | null; signature: string | null; method: string; path: string }): BPCRequestData {
  return {
    version: BPC_PROTOCOL_VERSION,
    bodyHash: null,
    ...overrides,
  };
}

// --- Test suite ---

describe('@bpc/server — verifyBPCRequest', () => {
  let registry: PairRegistry;
  let nonceStore: ServerNonceStore;
  let anomaly: AnomalyEngine;
  let keypair: Awaited<ReturnType<typeof generateKeypair>>;
  let pairId: string;
  let secretHash: string;

  beforeEach(async () => {
    const pairStore = new MemoryPairStore();
    const nonceBackend = new MemoryNonceBackend();
    const anomalyStore = new MemoryAnomalyStore();

    registry = new PairRegistry(pairStore);
    nonceStore = new ServerNonceStore(nonceBackend, 120_000);
    anomaly = new AnomalyEngine(anomalyStore);
    keypair = await generateKeypair();
    secretHash = await hashSecret('test-secret-abc123');

    // Register pair directly (dev mode)
    pairId = await registry.registerDirect({
      name: 'test-client',
      scope: 'read-write',
      mode: 'development',
      secretHash,
      pubJwk: keypair.pubJwk,
    });
  });

  it('should verify a correctly signed request', async () => {
    const { signedData, signature } = await buildSignedRequest(
      keypair.privateKey, pairId, 'GET', '/api/data', secretHash,
    );

    const req = makeReqData({
      pairId,
      signedData,
      signature,
      method: 'GET',
      path: '/api/data',
    });

    const result = await verifyBPCRequest(req, registry, nonceStore, anomaly);
    expect(result.ok).toBe(true);
    expect(result.pairId).toBe(pairId);
    expect(result.pair?.name).toBe('test-client');
  });

  it('should reject a replayed request (same nonce)', async () => {
    const { signedData, signature } = await buildSignedRequest(
      keypair.privateKey, pairId, 'GET', '/api/data', secretHash,
    );

    const req = makeReqData({
      pairId,
      signedData,
      signature,
      method: 'GET',
      path: '/api/data',
    });

    // First request succeeds
    const first = await verifyBPCRequest(req, registry, nonceStore, anomaly);
    expect(first.ok).toBe(true);

    // Replay with identical nonce fails
    const second = await verifyBPCRequest(req, registry, nonceStore, anomaly);
    expect(second.ok).toBe(false);
    expect(second.error).toBe('replay_detected');
  });

  it('should reject a tampered payload (modified path after signing)', async () => {
    const { signedData, signature } = await buildSignedRequest(
      keypair.privateKey, pairId, 'GET', '/api/data', secretHash,
    );

    // Attacker changes the path in the request but uses original signed data
    const req = makeReqData({
      pairId,
      signedData,
      signature,
      method: 'GET',
      path: '/api/admin', // tampered — does not match signed payload
    });

    const result = await verifyBPCRequest(req, registry, nonceStore, anomaly);
    expect(result.ok).toBe(false);
    expect(result.error).toBe('method_path_mismatch');
  });

  it('should reject an expired timestamp', async () => {
    const nonce = generateNonce();
    const timestamp = Date.now() - 120_000; // 2 minutes ago, well outside 60s window
    const bodyHash = b64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode('')));
    const secretHmac = await hmacDerive(secretHash, nonce + timestamp);

    const payload: BPCCanonicalPayload = {
      body_hash: bodyHash,
      method: 'GET',
      nonce,
      pair_id: pairId,
      path: '/api/data',
      secret_hmac: secretHmac,
      timestamp,
      version: BPC_PROTOCOL_VERSION,
    };

    const signature = await signPayload(keypair.privateKey, payload as unknown as Record<string, unknown>);
    const signedData = encodePayload(payload as unknown as Record<string, unknown>);

    const req = makeReqData({
      pairId,
      signedData,
      signature,
      method: 'GET',
      path: '/api/data',
    });

    const result = await verifyBPCRequest(req, registry, nonceStore, anomaly);
    expect(result.ok).toBe(false);
    expect(result.error).toBe('timestamp_expired');
  });

  it('should reject an unknown pair ID', async () => {
    const { signedData, signature } = await buildSignedRequest(
      keypair.privateKey, pairId, 'GET', '/api/data', secretHash,
    );

    const req = makeReqData({
      pairId: 'pair_does_not_exist',
      signedData,
      signature,
      method: 'GET',
      path: '/api/data',
    });

    const result = await verifyBPCRequest(req, registry, nonceStore, anomaly);
    expect(result.ok).toBe(false);
    expect(result.error).toBe('unknown_pair');
  });

  it('should reject a request with a forged signature', async () => {
    // Generate a different keypair — attacker's key
    const attackerKeypair = await generateKeypair();

    const { signedData, signature } = await buildSignedRequest(
      attackerKeypair.privateKey, pairId, 'GET', '/api/data', secretHash,
    );

    const req = makeReqData({
      pairId,
      signedData,
      signature, // signed with attacker's key, server has legitimate pair's pubkey
      method: 'GET',
      path: '/api/data',
    });

    const result = await verifyBPCRequest(req, registry, nonceStore, anomaly);
    expect(result.ok).toBe(false);
    expect(result.error).toBe('invalid_signature');
  });

  it('should reject a request with missing headers', async () => {
    const req = makeReqData({
      pairId: null,
      signedData: null,
      signature: null,
      method: 'GET',
      path: '/api/data',
    });

    const result = await verifyBPCRequest(req, registry, nonceStore, anomaly);
    expect(result.ok).toBe(false);
    expect(result.error).toBe('missing_headers');
  });

  it('should reject a revoked pair', async () => {
    await registry.revoke(pairId);

    const { signedData, signature } = await buildSignedRequest(
      keypair.privateKey, pairId, 'GET', '/api/data', secretHash,
    );

    const req = makeReqData({
      pairId,
      signedData,
      signature,
      method: 'GET',
      path: '/api/data',
    });

    const result = await verifyBPCRequest(req, registry, nonceStore, anomaly);
    expect(result.ok).toBe(false);
    expect(result.error).toBe('pair_revoked');
  });

  it('should reject a body hash mismatch', async () => {
    const { signedData, signature } = await buildSignedRequest(
      keypair.privateKey, pairId, 'GET', '/api/data', secretHash,
    );

    const req = makeReqData({
      pairId,
      signedData,
      signature,
      method: 'GET',
      path: '/api/data',
      bodyHash: 'tampered_body_hash_value', // does not match payload body_hash
    });

    const result = await verifyBPCRequest(req, registry, nonceStore, anomaly);
    expect(result.ok).toBe(false);
    expect(result.error).toBe('invalid_body_hash');
  });

  it('should reject DELETE on a read-only scoped pair', async () => {
    // Register a read-only pair
    const readKeypair = await generateKeypair();
    const readSH = await hashSecret('read-only-secret');
    const readPairId = await registry.registerDirect({
      name: 'read-only-client',
      scope: 'read',
      mode: 'development',
      secretHash: readSH,
      pubJwk: readKeypair.pubJwk,
    });

    const { signedData, signature } = await buildSignedRequest(
      readKeypair.privateKey, readPairId, 'DELETE', '/api/data', readSH,
    );

    const req = makeReqData({
      pairId: readPairId,
      signedData,
      signature,
      method: 'DELETE',
      path: '/api/data',
    });

    const result = await verifyBPCRequest(req, registry, nonceStore, anomaly);
    expect(result.ok).toBe(false);
    expect(result.error).toBe('scope_violation');
  });

  it('should lock a pair after 10 consecutive signature failures', async () => {
    const attackerKeypair = await generateKeypair();

    for (let i = 0; i < 10; i++) {
      const { signedData, signature } = await buildSignedRequest(
        attackerKeypair.privateKey, pairId, 'GET', '/api/data', secretHash,
      );
      const req = makeReqData({
        pairId,
        signedData,
        signature,
        method: 'GET',
        path: '/api/data',
      });
      const result = await verifyBPCRequest(req, registry, nonceStore, anomaly);
      expect(result.ok).toBe(false);
      expect(result.error).toBe('invalid_signature');
    }

    // Pair should now be locked
    const pair = await registry.get(pairId);
    expect(pair?.status).toBe('locked');

    // Next request should get pair_locked
    const { signedData, signature } = await buildSignedRequest(
      keypair.privateKey, pairId, 'GET', '/api/data', secretHash,
    );
    const req = makeReqData({
      pairId,
      signedData,
      signature,
      method: 'GET',
      path: '/api/data',
    });
    const result = await verifyBPCRequest(req, registry, nonceStore, anomaly);
    expect(result.ok).toBe(false);
    expect(result.error).toBe('pair_locked');
  });

  it('should reject requests when rate limited', async () => {
    // Rate limiter: 1 request per 60s window
    const rateLimiter = new MemoryRateLimiter(1, 60_000);

    const { signedData: sd1, signature: sig1 } = await buildSignedRequest(
      keypair.privateKey, pairId, 'GET', '/api/data', secretHash,
    );
    const req1 = makeReqData({
      pairId,
      signedData: sd1,
      signature: sig1,
      method: 'GET',
      path: '/api/data',
      ip: '127.0.0.1',
    });

    // First request passes
    const r1 = await verifyBPCRequest(req1, registry, nonceStore, anomaly, {
      sigWindowMs: 60_000,
      rateLimiter,
    });
    expect(r1.ok).toBe(true);

    // Second request from same IP gets rate limited
    const { signedData: sd2, signature: sig2 } = await buildSignedRequest(
      keypair.privateKey, pairId, 'GET', '/api/data', secretHash,
    );
    const req2 = makeReqData({
      pairId,
      signedData: sd2,
      signature: sig2,
      method: 'GET',
      path: '/api/data',
      ip: '127.0.0.1',
    });
    const r2 = await verifyBPCRequest(req2, registry, nonceStore, anomaly, {
      sigWindowMs: 60_000,
      rateLimiter,
    });
    expect(r2.ok).toBe(false);
    expect(r2.error).toBe('rate_limit_exceeded');
  });

  it('should reject an expired pair (expiresAt in the past)', async () => {
    // Register a pair that has already expired
    const expKeypair = await generateKeypair();
    const expSH = await hashSecret('expired-secret');
    const expPairId = await registry.registerDirect({
      name: 'expired-client',
      scope: 'admin',
      mode: 'development',
      secretHash: expSH,
      pubJwk: expKeypair.pubJwk,
      expiresAt: Date.now() - 1000, // expired 1 second ago
    });

    const { signedData, signature } = await buildSignedRequest(
      expKeypair.privateKey, expPairId, 'GET', '/api/data', expSH,
    );

    const req = makeReqData({
      pairId: expPairId,
      signedData,
      signature,
      method: 'GET',
      path: '/api/data',
    });

    const result = await verifyBPCRequest(req, registry, nonceStore, anomaly);
    expect(result.ok).toBe(false);
    expect(result.error).toBe('pair_expired');
  });

  it('should reject a version mismatch', async () => {
    const { signedData, signature } = await buildSignedRequest(
      keypair.privateKey, pairId, 'GET', '/api/data', secretHash,
    );

    const req = makeReqData({
      pairId,
      signedData,
      signature,
      method: 'GET',
      path: '/api/data',
      version: '0.0.1', // wrong version
    });

    const result = await verifyBPCRequest(req, registry, nonceStore, anomaly);
    expect(result.ok).toBe(false);
    expect(result.error).toBe('version_mismatch');
  });

  it('should reject an oversized X-BPC-Signed-Data header (DoS guard)', async () => {
    const req = makeReqData({
      pairId,
      signedData: 'A'.repeat(4097),  // exceeds 4096-char limit
      signature: 'sig',
      method: 'GET',
      path: '/api/data',
    });
    const result = await verifyBPCRequest(req, registry, nonceStore, anomaly);
    expect(result.ok).toBe(false);
    expect(result.error).toBe('invalid_signed_data');
  });

  it('should reject an oversized X-BPC-Signature header (DoS guard)', async () => {
    const { signedData } = await buildSignedRequest(keypair.privateKey, pairId, 'GET', '/api/data', secretHash);
    const req = makeReqData({
      pairId,
      signedData,
      signature: 'A'.repeat(257),   // exceeds 256-char limit
      method: 'GET',
      path: '/api/data',
    });
    const result = await verifyBPCRequest(req, registry, nonceStore, anomaly);
    expect(result.ok).toBe(false);
    expect(result.error).toBe('invalid_signed_data');
  });

  it('should lock via failedSigs check even if status field lags (parallel-race guard)', async () => {
    // Manually set failedSigs to lockoutCount without changing status
    // (simulates the state mid-race where status hasn't been written back yet)
    const pair = await registry.get(pairId);
    if (pair) {
      pair.failedSigs = 10;
      // Don't set status=locked — simulate mid-race state
    }

    const { signedData, signature } = await buildSignedRequest(
      keypair.privateKey, pairId, 'GET', '/api/data', secretHash,
    );
    const req = makeReqData({ pairId, signedData, signature, method: 'GET', path: '/api/data' });
    const result = await verifyBPCRequest(req, registry, nonceStore, anomaly, { sigWindowMs: 60_000, lockoutCount: 10 });
    expect(result.ok).toBe(false);
    expect(result.error).toBe('pair_locked');
  });
});

describe('@bpc/server — PairRegistry', () => {
  it('should support approval workflow', async () => {
    const store = new MemoryPairStore();
    const registry = new PairRegistry(store);
    const kp = await generateKeypair();
    const sh = await hashSecret('approval-test');

    const token = await registry.requestPairing({
      name: 'pending-client',
      scope: 'read',
      mode: 'production',
      secretHash: sh,
      pubJwk: kp.pubJwk,
    });

    // Pending list has our request
    const pending = await registry.listPending();
    expect(pending.length).toBe(1);
    expect(pending[0].token).toBe(token);

    // Approve it
    const id = await registry.approvePairing(token);
    const pair = await registry.get(id);
    expect(pair?.name).toBe('pending-client');
    const pendingAfter = await registry.listPending();
    expect(pendingAfter.length).toBe(0);
  });

  it('should throw on invalid approval token', async () => {
    const store = new MemoryPairStore();
    const registry = new PairRegistry(store);
    await expect(registry.approvePairing('bogus_token')).rejects.toThrow('No pending approval');
  });

  it('should unlock a locked pair', async () => {
    const store = new MemoryPairStore();
    const registry = new PairRegistry(store, 2000, 2); // lockout after 2 failures
    const kp = await generateKeypair();
    const sh = await hashSecret('lockout-test');

    const id = await registry.registerDirect({
      name: 'lockout-client',
      scope: 'admin',
      mode: 'development',
      secretHash: sh,
      pubJwk: kp.pubJwk,
    });

    // Fail twice to trigger lockout
    await registry.recordActivity(id, false);
    await registry.recordActivity(id, false);
    let pair = await registry.get(id);
    expect(pair?.status).toBe('locked');

    // Unlock
    await registry.unlock(id);
    pair = await registry.get(id);
    expect(pair?.status).toBe('active');
    expect(pair?.failedSigs).toBe(0);
  });
});

describe('@bpc/server — AnomalyEngine', () => {
  it('should return 0 threat score with no requests', async () => {
    const store = new MemoryAnomalyStore();
    const engine = new AnomalyEngine(store);
    expect(await engine.threatScore()).toBe(0);
  });

  it('should increase threat score with failures', async () => {
    const store = new MemoryAnomalyStore();
    const engine = new AnomalyEngine(store);
    // 10 total requests, all bad
    for (let i = 0; i < 10; i++) {
      await engine.recordRequest();
      await engine.recordSigFailure();
      await engine.recordUnknownPair();
    }
    const score = await engine.threatScore();
    // unknownRate=1 (30pts) + sigRate=1 (30pts) + replay=0 + expired=0 = 60 * 100 = 6000
    expect(score).toBe(6000);
  });

  it('should track counters accurately', async () => {
    const store = new MemoryAnomalyStore();
    const engine = new AnomalyEngine(store);
    await engine.recordRequest();
    await engine.recordRequest();
    await engine.recordDenied();
    await engine.recordReplay();
    const c = await engine.counters();
    expect(c.totalRequests).toBe(2);
    expect(c.deniedRequests).toBe(1);
    expect(c.replayAttempts).toBe(1);
  });

  it('should track per-pair counters', async () => {
    const store = new MemoryAnomalyStore();
    const engine = new AnomalyEngine(store);
    await engine.recordRequest('pair_abc');
    await engine.recordRequest('pair_abc');
    await engine.recordSigFailure('pair_abc');
    await engine.recordRequest('pair_xyz');

    const abc = await engine.pairCounters('pair_abc');
    expect(abc.total).toBe(2);
    expect(abc.sigFail).toBe(1);

    const xyz = await engine.pairCounters('pair_xyz');
    expect(xyz.total).toBe(1);
    expect(xyz.sigFail).toBe(0);
  });
});

describe('@bpc/server — MemoryRateLimiter', () => {
  it('should allow requests within limit', async () => {
    const limiter = new MemoryRateLimiter(5, 60_000);
    for (let i = 0; i < 5; i++) {
      const r = await limiter.check('test-key');
      expect(r.allowed).toBe(true);
      expect(r.remaining).toBe(4 - i);
    }
    // 6th request denied
    const r = await limiter.check('test-key');
    expect(r.allowed).toBe(false);
    expect(r.remaining).toBe(0);
  });
});

describe('@bpc/server — ServerNonceStore', () => {
  it('should detect replay nonces', async () => {
    const backend = new MemoryNonceBackend();
    const store = new ServerNonceStore(backend, 60_000);

    const replay1 = await store.checkAndConsume('nonce-1');
    expect(replay1).toBe(false); // fresh

    const replay2 = await store.checkAndConsume('nonce-1');
    expect(replay2).toBe(true); // replay

    const replay3 = await store.checkAndConsume('nonce-2');
    expect(replay3).toBe(false); // different nonce, fresh
  });
});
