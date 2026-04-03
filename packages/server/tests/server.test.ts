import { describe, it, expect, beforeEach } from 'vitest';
import {
  generateKeypair,
  signPayload,
  canonicalize,
  hashSecret,
  hmacDerive,
  generateNonce,
  b64url,
} from '../../core/src/index.js';
import type { BPCCanonicalPayload } from '../../core/src/types.js';
import { PairRegistry } from '../src/registry.js';
import { ServerNonceStore } from '../src/nonce-store.js';
import { AnomalyEngine } from '../src/anomaly.js';
import { verifyBPCRequest } from '../src/middleware.js';
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
  };

  const signature = await signPayload(privateKey, payload as unknown as Record<string, unknown>);
  const signedData = encodePayload(payload as unknown as Record<string, unknown>);

  return { payload, signedData, signature };
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
    registry = new PairRegistry();
    nonceStore = new ServerNonceStore(120_000);
    anomaly = new AnomalyEngine();
    keypair = await generateKeypair();
    secretHash = await hashSecret('test-secret-abc123');

    // Register pair directly (dev mode)
    pairId = registry.registerDirect({
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

    const req: BPCRequestData = {
      pairId,
      signedData,
      signature,
      method: 'GET',
      path: '/api/data',
    };

    const result = await verifyBPCRequest(req, registry, nonceStore, anomaly);
    expect(result.ok).toBe(true);
    expect(result.pairId).toBe(pairId);
    expect(result.pair?.name).toBe('test-client');
  });

  it('should reject a replayed request (same nonce)', async () => {
    const { signedData, signature } = await buildSignedRequest(
      keypair.privateKey, pairId, 'GET', '/api/data', secretHash,
    );

    const req: BPCRequestData = {
      pairId,
      signedData,
      signature,
      method: 'GET',
      path: '/api/data',
    };

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
    const req: BPCRequestData = {
      pairId,
      signedData,
      signature,
      method: 'GET',
      path: '/api/admin', // tampered — does not match signed payload
    };

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
    };

    const signature = await signPayload(keypair.privateKey, payload as unknown as Record<string, unknown>);
    const signedData = encodePayload(payload as unknown as Record<string, unknown>);

    const req: BPCRequestData = {
      pairId,
      signedData,
      signature,
      method: 'GET',
      path: '/api/data',
    };

    const result = await verifyBPCRequest(req, registry, nonceStore, anomaly);
    expect(result.ok).toBe(false);
    expect(result.error).toBe('timestamp_expired');
  });

  it('should reject an unknown pair ID', async () => {
    const { signedData, signature } = await buildSignedRequest(
      keypair.privateKey, pairId, 'GET', '/api/data', secretHash,
    );

    const req: BPCRequestData = {
      pairId: 'pair_does_not_exist',
      signedData,
      signature,
      method: 'GET',
      path: '/api/data',
    };

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

    const req: BPCRequestData = {
      pairId,
      signedData,
      signature, // signed with attacker's key, server has legitimate pair's pubkey
      method: 'GET',
      path: '/api/data',
    };

    const result = await verifyBPCRequest(req, registry, nonceStore, anomaly);
    expect(result.ok).toBe(false);
    expect(result.error).toBe('invalid_signature');
  });

  it('should reject a request with missing headers', async () => {
    const req: BPCRequestData = {
      pairId: null,
      signedData: null,
      signature: null,
      method: 'GET',
      path: '/api/data',
    };

    const result = await verifyBPCRequest(req, registry, nonceStore, anomaly);
    expect(result.ok).toBe(false);
    expect(result.error).toBe('missing_headers');
  });

  it('should reject a revoked pair', async () => {
    registry.revoke(pairId);

    const { signedData, signature } = await buildSignedRequest(
      keypair.privateKey, pairId, 'GET', '/api/data', secretHash,
    );

    const req: BPCRequestData = {
      pairId,
      signedData,
      signature,
      method: 'GET',
      path: '/api/data',
    };

    const result = await verifyBPCRequest(req, registry, nonceStore, anomaly);
    expect(result.ok).toBe(false);
    expect(result.error).toBe('pair_revoked');
  });
});

describe('@bpc/server — PairRegistry', () => {
  it('should support approval workflow', async () => {
    const registry = new PairRegistry();
    const kp = await generateKeypair();
    const sh = await hashSecret('approval-test');

    const token = registry.requestPairing({
      name: 'pending-client',
      scope: 'read',
      mode: 'production',
      secretHash: sh,
      pubJwk: kp.pubJwk,
    });

    // Pending list has our request
    const pending = registry.listPending();
    expect(pending.length).toBe(1);
    expect(pending[0].token).toBe(token);

    // Approve it
    const id = registry.approvePairing(token);
    expect(registry.get(id)?.name).toBe('pending-client');
    expect(registry.listPending().length).toBe(0);
  });

  it('should throw on invalid approval token', () => {
    const registry = new PairRegistry();
    expect(() => registry.approvePairing('bogus_token')).toThrow('No pending approval');
  });
});

describe('@bpc/server — AnomalyEngine', () => {
  it('should return 0 threat score with no requests', () => {
    const engine = new AnomalyEngine();
    expect(engine.threatScore()).toBe(0);
  });

  it('should increase threat score with failures', () => {
    const engine = new AnomalyEngine();
    // 10 total requests, all bad
    for (let i = 0; i < 10; i++) {
      engine.recordRequest();
      engine.recordSigFailure();
      engine.recordUnknownPair();
    }
    const score = engine.threatScore();
    // unknownRate=1 (30pts) + sigRate=1 (30pts) + replay=0 + expired=0 = 60 * 100 = 6000
    expect(score).toBe(6000);
  });

  it('should track counters accurately', () => {
    const engine = new AnomalyEngine();
    engine.recordRequest();
    engine.recordRequest();
    engine.recordDenied();
    engine.recordReplay();
    const c = engine.counters();
    expect(c.totalRequests).toBe(2);
    expect(c.deniedRequests).toBe(1);
    expect(c.replayAttempts).toBe(1);
  });
});
