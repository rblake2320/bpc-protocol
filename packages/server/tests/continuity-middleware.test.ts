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
import { verifyBPCRequest, type BPCRequestData, type BPCServerConfig } from '../src/middleware.js';
import { MemoryPairStore, MemoryNonceBackend, MemoryAnomalyStore } from '../src/memory-store.js';
import { AuthorizationQuarantineError, type ContinuityGate } from '../src/redis-continuity.js';

function encodePayload(payload: Record<string, unknown>): string {
  const bytes = new TextEncoder().encode(canonicalize(payload));
  const binary = String.fromCharCode(...bytes);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

async function buildSignedRequest(privateKey: CryptoKey, pairId: string, secretHash: string) {
  const nonce = generateNonce();
  const timestamp = Date.now();
  const bodyHash = b64url(await crypto.subtle.digest('SHA-256', new TextEncoder().encode('')));
  const secret_hmac = await hmacDerive(secretHash, nonce + timestamp);
  const payload: BPCCanonicalPayload = {
    body_hash: bodyHash, method: 'GET', nonce, pair_id: pairId, path: '/api/data',
    secret_hmac, timestamp, version: BPC_PROTOCOL_VERSION,
  };
  const signature = await signPayload(privateKey, payload as unknown as Record<string, unknown>);
  const signedData = encodePayload(payload as unknown as Record<string, unknown>);
  return { signedData, signature, bodyHash };
}

function makeReq(pairId: string, signedData: string, signature: string, bodyHash: string): BPCRequestData {
  return {
    version: BPC_PROTOCOL_VERSION, pairId, signedData, signature,
    method: 'GET', path: '/api/data', bodyHash,
  };
}

const ACCEPTABLE: ContinuityGate = { assertAcceptable() {} };
const QUARANTINED: ContinuityGate = {
  assertAcceptable() { throw new AuthorizationQuarantineError('continuity_marker_lost', 1); },
};

describe('verifyBPCRequest — continuity gate wiring (#13)', () => {
  let registry: PairRegistry;
  let nonceStore: ServerNonceStore;
  let anomaly: AnomalyEngine;
  let keypair: Awaited<ReturnType<typeof generateKeypair>>;
  let pairId: string;
  let secretHash: string;
  const cfg = (guard?: ContinuityGate): BPCServerConfig => ({ sigWindowMs: 60_000, continuityGuard: guard });

  beforeEach(async () => {
    registry = new PairRegistry(new MemoryPairStore());
    nonceStore = new ServerNonceStore(new MemoryNonceBackend(), 120_000);
    anomaly = new AnomalyEngine(new MemoryAnomalyStore());
    keypair = await generateKeypair();
    secretHash = await hashSecret('test-secret-abc123');
    pairId = await registry.registerDirect({
      name: 'c', scope: 'read-write', mode: 'development', secretHash, pubJwk: keypair.pubJwk,
    });
  });

  it('denies fail-closed while quarantined', async () => {
    const { signedData, signature, bodyHash } = await buildSignedRequest(keypair.privateKey, pairId, secretHash);
    const result = await verifyBPCRequest(makeReq(pairId, signedData, signature, bodyHash), registry, nonceStore, anomaly, cfg(QUARANTINED));
    expect(result.ok).toBe(false);
    expect(result.error).toBe('authorization_quarantined');
  });

  it('does NOT consume the nonce during quarantine (so it works once quarantine lifts)', async () => {
    const { signedData, signature, bodyHash } = await buildSignedRequest(keypair.privateKey, pairId, secretHash);
    const req = makeReq(pairId, signedData, signature, bodyHash);

    const denied = await verifyBPCRequest(req, registry, nonceStore, anomaly, cfg(QUARANTINED));
    expect(denied.error).toBe('authorization_quarantined');

    // Same request replayed after quarantine lifts must still be accepted:
    // the gate ran BEFORE checkAndConsume, so the nonce was never spent.
    const ok = await verifyBPCRequest(req, registry, nonceStore, anomaly, cfg(ACCEPTABLE));
    expect(ok.ok).toBe(true);
  });

  it('accepts normally with an acceptable gate (happy path unaffected)', async () => {
    const { signedData, signature, bodyHash } = await buildSignedRequest(keypair.privateKey, pairId, secretHash);
    const result = await verifyBPCRequest(makeReq(pairId, signedData, signature, bodyHash), registry, nonceStore, anomaly, cfg(ACCEPTABLE));
    expect(result.ok).toBe(true);
  });

  it('behaves exactly as before when no guard is configured (non-breaking)', async () => {
    const { signedData, signature, bodyHash } = await buildSignedRequest(keypair.privateKey, pairId, secretHash);
    const result = await verifyBPCRequest(makeReq(pairId, signedData, signature, bodyHash), registry, nonceStore, anomaly, { sigWindowMs: 60_000 });
    expect(result.ok).toBe(true);
  });
});
