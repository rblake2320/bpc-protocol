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
import type { SuccessfulUsePolicy } from '../src/store.js';

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
): Promise<{ payload: BPCCanonicalPayload; signedData: string; signature: string; bodyHash: string }> {
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

  return { payload, signedData, signature, bodyHash };
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
  let pairStore: MemoryPairStore;
  let keypair: Awaited<ReturnType<typeof generateKeypair>>;
  let pairId: string;
  let secretHash: string;

  beforeEach(async () => {
    pairStore = new MemoryPairStore();
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
    const { signedData, signature, bodyHash } = await buildSignedRequest(
      keypair.privateKey, pairId, 'GET', '/api/data', secretHash,
    );

    const req = makeReqData({
      pairId,
      signedData,
      signature,
      method: 'GET',
      path: '/api/data',
      bodyHash,
    });

    const result = await verifyBPCRequest(req, registry, nonceStore, anomaly);
    expect(result.ok).toBe(true);
    expect(result.pairId).toBe(pairId);
    expect(result.snapshot).toEqual(expect.objectContaining({
      pairId,
      scope: 'read-write',
      mode: 'development',
      kind: 'legitimate',
    }));
    expect(Object.isFrozen(result.snapshot)).toBe(true);
    expect('pair' in result).toBe(false);
  });

  it('denies when authorization policy mutates after verification begins', async () => {
    const replacementKeypair = await generateKeypair();
    let signalNonceCheck!: () => void;
    let releaseNonceCheck!: () => void;
    const nonceCheckStarted = new Promise<void>((resolve) => { signalNonceCheck = resolve; });
    const nonceCheckRelease = new Promise<void>((resolve) => { releaseNonceCheck = resolve; });
    const blockingNonceStore = new ServerNonceStore({
      async checkAndConsume() {
        signalNonceCheck();
        await nonceCheckRelease;
        return false;
      },
    }, 120_000);
    const { signedData, signature, bodyHash } = await buildSignedRequest(
      keypair.privateKey, pairId, 'GET', '/api/data', secretHash,
    );

    const verification = verifyBPCRequest(makeReqData({
      pairId,
      signedData,
      signature,
      method: 'GET',
      path: '/api/data',
      bodyHash,
    }), registry, blockingNonceStore, anomaly);

    await nonceCheckStarted;
    await pairStore.atomicMutate(pairId, (current) => ({
      ...current,
      scope: 'admin',
      mode: 'production',
      secretHash: 'z'.repeat(43),
      pubJwk: replacementKeypair.pubJwk,
      name: 'mutated-after-authorization',
    }));
    releaseNonceCheck();

    const result = await verification;
    expect(result).toMatchObject({ ok: false, error: 'pair_state_changed_retry' });
    expect(await registry.get(pairId)).toMatchObject({
      scope: 'admin', mode: 'production', secretHash: 'z'.repeat(43), requests: 0,
    });
  });

  it('does not authorize a method enabled only by a concurrent scope escalation', async () => {
    let signalPolicyPause!: () => void;
    let releasePolicyPause!: () => void;
    const policyPaused = new Promise<void>((resolve) => { signalPolicyPause = resolve; });
    const policyRelease = new Promise<void>((resolve) => { releasePolicyPause = resolve; });
    anomaly.getVerdict = async () => {
      signalPolicyPause();
      await policyRelease;
      return 'clean';
    };
    const { signedData, signature, bodyHash } = await buildSignedRequest(
      keypair.privateKey, pairId, 'DELETE', '/api/admin', secretHash,
    );

    const verification = verifyBPCRequest(makeReqData({
      pairId,
      signedData,
      signature,
      method: 'DELETE',
      path: '/api/admin',
      bodyHash,
      ip: '127.0.0.1',
    }), registry, nonceStore, anomaly);

    await policyPaused;
    await registry.updatePair(pairId, { scope: 'admin' });
    releasePolicyPause();

    const result = await verification;
    expect(result).toEqual({ ok: false, error: 'scope_violation' });
    expect((await registry.get(pairId))?.scope).toBe('admin');
  });

  it('does not turn the health path into an unauthenticated authorization result', async () => {
    const result = await verifyBPCRequest(makeReqData({
      pairId: null,
      signedData: null,
      signature: null,
      method: 'GET',
      path: '/health',
    }), registry, nonceStore, anomaly);

    expect(result).toEqual({ ok: false, error: 'missing_headers' });
    expect(result.snapshot).toBeUndefined();
  });

  it('should reject a replayed request (same nonce)', async () => {
    const { signedData, signature, bodyHash } = await buildSignedRequest(
      keypair.privateKey, pairId, 'GET', '/api/data', secretHash,
    );

    const req = makeReqData({
      pairId,
      signedData,
      signature,
      method: 'GET',
      path: '/api/data',
      bodyHash,
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

    const { signedData, signature, bodyHash } = await buildSignedRequest(
      attackerKeypair.privateKey, pairId, 'GET', '/api/data', secretHash,
    );

    const req = makeReqData({
      pairId,
      signedData,
      signature, // signed with attacker's key, server has legitimate pair's pubkey
      method: 'GET',
      path: '/api/data',
      bodyHash, // provide the body hash so we reach the signature check
    });

    const result = await verifyBPCRequest(req, registry, nonceStore, anomaly);
    expect(result.ok).toBe(false);
    expect(result.error).toBe('invalid_signature');
  });

  it('does not consume a legitimate nonce when the signature is invalid', async () => {
    const { signedData, signature, bodyHash } = await buildSignedRequest(
      keypair.privateKey, pairId, 'GET', '/api/data', secretHash,
    );
    const forged = signature.slice(0, -2) + (signature.endsWith('AA') ? 'BB' : 'AA');

    const rejected = await verifyBPCRequest(makeReqData({
      pairId, signedData, signature: forged, method: 'GET', path: '/api/data', bodyHash,
    }), registry, nonceStore, anomaly, { enableShadowMode: false, enableTarpit: false, sigWindowMs: 60_000 });
    expect(rejected.error).toBe('invalid_signature');

    const accepted = await verifyBPCRequest(makeReqData({
      pairId, signedData, signature, method: 'GET', path: '/api/data', bodyHash,
    }), registry, nonceStore, anomaly, { enableShadowMode: false, enableTarpit: false, sigWindowMs: 60_000 });
    expect(accepted.ok).toBe(true);
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

  it('rejects a signed payload whose pair ID differs from the authenticated header pair', async () => {
    const { signedData, signature, bodyHash } = await buildSignedRequest(
      keypair.privateKey, 'pair_other_identity', 'GET', '/api/data', secretHash,
    );

    const result = await verifyBPCRequest(makeReqData({
      pairId,
      signedData,
      signature,
      method: 'GET',
      path: '/api/data',
      bodyHash,
    }), registry, nonceStore, anomaly);
    expect(result.ok).toBe(false);
    expect(result.error).toBe('pair_id_mismatch');
  });

  it('rejects a request when the transport does not provide the actual body hash', async () => {
    const { signedData, signature } = await buildSignedRequest(
      keypair.privateKey, pairId, 'GET', '/api/data', secretHash,
    );

    const result = await verifyBPCRequest(makeReqData({
      pairId,
      signedData,
      signature,
      method: 'GET',
      path: '/api/data',
      bodyHash: null,
    }), registry, nonceStore, anomaly);
    expect(result.ok).toBe(false);
    expect(result.error).toBe('missing_body_hash');
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
      const { signedData, signature, bodyHash } = await buildSignedRequest(
        attackerKeypair.privateKey, pairId, 'GET', '/api/data', secretHash,
      );
      const req = makeReqData({
        pairId,
        signedData,
        signature,
        method: 'GET',
        path: '/api/data',
        bodyHash, // provide body hash so we reach the signature check
      });
      const result = await verifyBPCRequest(req, registry, nonceStore, anomaly);
      expect(result.ok).toBe(false);
      expect(result.error).toBe('invalid_signature');
    }

    // Pair should now be locked
    const pair = await registry.get(pairId);
    expect(pair?.status).toBe('locked');

    // Shadow metadata never converts a locked credential into an authorization success.
    const { signedData, signature, bodyHash } = await buildSignedRequest(
      keypair.privateKey, pairId, 'GET', '/api/data', secretHash,
    );
    const req = makeReqData({
      pairId,
      signedData,
      signature,
      method: 'GET',
      path: '/api/data',
      bodyHash,
    });
    const result = await verifyBPCRequest(req, registry, nonceStore, anomaly);
    expect(result.ok).toBe(false);
    expect(result.error).toBe('pair_locked');
    expect(result.shadow).toBe(true);

    // With Shadow Mode explicitly disabled, the raw pair_locked error is returned.
    const result2 = await verifyBPCRequest(req, registry, nonceStore, anomaly, {
      sigWindowMs: 60_000,
      enableShadowMode: false,
    });
    expect(result2.ok).toBe(false);
    expect(result2.error).toBe('pair_locked');
  });

  it('should reject requests when rate limited', async () => {
    // Rate limiter: 1 request per 60s window
    const rateLimiter = new MemoryRateLimiter(1, 60_000);

    const { signedData: sd1, signature: sig1, bodyHash: bh1 } = await buildSignedRequest(
      keypair.privateKey, pairId, 'GET', '/api/data', secretHash,
    );
    const req1 = makeReqData({
      pairId,
      signedData: sd1,
      signature: sig1,
      method: 'GET',
      path: '/api/data',
      ip: '127.0.0.1',
      bodyHash: bh1,
    });

    // First request passes
    const r1 = await verifyBPCRequest(req1, registry, nonceStore, anomaly, {
      sigWindowMs: 60_000,
      rateLimiter,
    });
    expect(r1.ok).toBe(true);

    // Second request from same IP gets rate limited
    const { signedData: sd2, signature: sig2, bodyHash: bh2 } = await buildSignedRequest(
      keypair.privateKey, pairId, 'GET', '/api/data', secretHash,
    );
    const req2 = makeReqData({
      pairId,
      signedData: sd2,
      signature: sig2,
      method: 'GET',
      path: '/api/data',
      ip: '127.0.0.1',
      bodyHash: bh2,
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
    expect((await registry.get(expPairId))?.status).toBe('expired');
  });

  it('should expire a pair after its maxRequests cap is exhausted', async () => {
    const cappedKeypair = await generateKeypair();
    const cappedSecretHash = await hashSecret('capped-secret');
    const cappedPairId = await registry.registerDirect({
      name: 'capped-client',
      scope: 'read-write',
      mode: 'development',
      secretHash: cappedSecretHash,
      pubJwk: cappedKeypair.pubJwk,
      maxRequests: 1,
    });

    const firstSigned = await buildSignedRequest(
      cappedKeypair.privateKey, cappedPairId, 'GET', '/api/data', cappedSecretHash,
    );
    const first = await verifyBPCRequest(
      makeReqData({
        pairId: cappedPairId,
        signedData: firstSigned.signedData,
        signature: firstSigned.signature,
        method: 'GET',
        path: '/api/data',
        bodyHash: firstSigned.bodyHash,
      }),
      registry,
      nonceStore,
      anomaly,
    );
    expect(first.ok).toBe(true);
    const exhaustedPair = await registry.get(cappedPairId);
    expect(exhaustedPair?.status).toBe('expired');
    expect(exhaustedPair?.requests).toBe(1);

    const secondSigned = await buildSignedRequest(
      cappedKeypair.privateKey, cappedPairId, 'GET', '/api/data', cappedSecretHash,
    );
    const second = await verifyBPCRequest(
      makeReqData({
        pairId: cappedPairId,
        signedData: secondSigned.signedData,
        signature: secondSigned.signature,
        method: 'GET',
        path: '/api/data',
        bodyHash: secondSigned.bodyHash,
      }),
      registry,
      nonceStore,
      anomaly,
    );
    expect(second.ok).toBe(false);
    expect(second.error).toBe('pair_expired');

    const cappedPair = await registry.get(cappedPairId);
    expect(cappedPair?.status).toBe('expired');
    expect(cappedPair?.requests).toBe(1);
  });

  it('persists expiry before returning the early usage-cap denial', async () => {
    const localStore=new MemoryPairStore(),localRegistry=new PairRegistry(localStore,10,10,true),localNonce=new ServerNonceStore(new MemoryNonceBackend(),120_000),localAnomaly=new AnomalyEngine(new MemoryAnomalyStore());
    const kp=await generateKeypair(),secret=await hashSecret('already-exhausted'),id=await localRegistry.registerDirect({name:'already-exhausted',scope:'read',mode:'production',secretHash:secret,pubJwk:kp.pubJwk,maxRequests:1});
    const current=await localRegistry.get(id);await localStore.set({...current!,requests:1,status:'active'});
    const signed=await buildSignedRequest(kp.privateKey,id,'GET','/api/data',secret);
    const result=await verifyBPCRequest(makeReqData({pairId:id,signedData:signed.signedData,signature:signed.signature,method:'GET',path:'/api/data',bodyHash:signed.bodyHash}),localRegistry,localNonce,localAnomaly);
    expect(result).toMatchObject({ok:false,error:'pair_usage_cap_exceeded'});
    expect((await localRegistry.get(id))?.status).toBe('expired');
  });

  it('returns the durable usage-cap reason to the concurrent final-cap loser', async () => {
    class FinalCapRaceStore extends MemoryPairStore {
      private entered = 0;
      private release!: () => void;
      private readonly bothEntered = new Promise<void>((resolve) => { this.release = resolve; });
      override async claimSuccessfulUse(id:string,at:number,expected:SuccessfulUsePolicy) {
        this.entered++;
        if (this.entered === 2) this.release();
        await this.bothEntered;
        return super.claimSuccessfulUse(id,at,expected);
      }
    }
    const localStore=new FinalCapRaceStore(),localRegistry=new PairRegistry(localStore,10,10,true),localNonce=new ServerNonceStore(new MemoryNonceBackend(),120_000),localAnomaly=new AnomalyEngine(new MemoryAnomalyStore());
    const kp=await generateKeypair(),secret=await hashSecret('final-cap-race'),id=await localRegistry.registerDirect({name:'final-cap-race',scope:'read',mode:'production',secretHash:secret,pubJwk:kp.pubJwk,maxRequests:1});
    const signed=await Promise.all([buildSignedRequest(kp.privateKey,id,'GET','/api/data',secret),buildSignedRequest(kp.privateKey,id,'GET','/api/data',secret)]);
    const results=await Promise.all(signed.map((request)=>verifyBPCRequest(makeReqData({pairId:id,signedData:request.signedData,signature:request.signature,method:'GET',path:'/api/data',bodyHash:request.bodyHash}),localRegistry,localNonce,localAnomaly)));
    expect(results.filter((result)=>result.ok)).toHaveLength(1);
    expect(results.filter((result)=>!result.ok)).toEqual([expect.objectContaining({error:'pair_usage_cap_exceeded'})]);
    expect(await localRegistry.get(id)).toMatchObject({status:'expired',requests:1});
  });

  it('denies when expiry elapses or is shortened after the verification snapshot but before the final claim', async () => {
    class ExpiryRaceStore extends MemoryPairStore {
      override async claimSuccessfulUse(id:string,at:number,expected:SuccessfulUsePolicy) {
        await this.atomicMutate(id,(pair)=>({...pair,expiresAt:at-1}));
        return super.claimSuccessfulUse(id,at,expected);
      }
    }
    const localStore=new ExpiryRaceStore(),localRegistry=new PairRegistry(localStore,10,10,true),localNonce=new ServerNonceStore(new MemoryNonceBackend(),120_000),localAnomaly=new AnomalyEngine(new MemoryAnomalyStore());
    const kp=await generateKeypair(),secret=await hashSecret('expiry-race'),id=await localRegistry.registerDirect({name:'expiry-race',scope:'read',mode:'production',secretHash:secret,pubJwk:kp.pubJwk,expiresAt:Date.now()+60_000});
    const signed=await buildSignedRequest(kp.privateKey,id,'GET','/api/data',secret);
    const result=await verifyBPCRequest(makeReqData({pairId:id,signedData:signed.signedData,signature:signed.signature,method:'GET',path:'/api/data',bodyHash:signed.bodyHash}),localRegistry,localNonce,localAnomaly);
    expect(result).toMatchObject({ok:false,error:'pair_expired'});
    expect(await localRegistry.get(id)).toMatchObject({status:'expired',requests:0});
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
    // ── Assertion 1: Shadow Mode OFF → raw pair_locked error ──────────────────
    // Use a fresh isolated pair so state is clean.
    const store1 = new MemoryPairStore();
    const registry1 = new PairRegistry(store1);
    const nonceStore1 = new ServerNonceStore(new MemoryNonceBackend(), 60_000);
    const anomaly1 = new AnomalyEngine(new MemoryAnomalyStore());
    const kp1 = await generateKeypair();
    const sh1 = await hashSecret('race-guard-secret-1');
    const raceId1 = await registry1.registerDirect({ name: 'race-1', scope: 'read', mode: 'development', secretHash: sh1, pubJwk: kp1.pubJwk });
    // Manually set failedSigs to lockoutCount without changing status
    const pair1 = await registry1.get(raceId1);
    if (pair1) { await store1.set({ ...pair1, failedSigs: 10 }); }
    const { signedData: sd1, signature: sig1 } = await buildSignedRequest(kp1.privateKey, raceId1, 'GET', '/api/data', sh1);
    const req1 = makeReqData({ pairId: raceId1, signedData: sd1, signature: sig1, method: 'GET', path: '/api/data' });
    const result = await verifyBPCRequest(req1, registry1, nonceStore1, anomaly1, { sigWindowMs: 60_000, lockoutCount: 10, enableShadowMode: false });
    expect(result.ok).toBe(false);
    expect(result.error).toBe('pair_locked');

    // ── Assertion 2: Shadow Mode ON remains a hard denial ────────────────────
    // Use a completely separate fresh pair so the first call's side-effects
    // (recordActivity overwriting failedSigs) do not contaminate this assertion.
    const store2 = new MemoryPairStore();
    const registry2 = new PairRegistry(store2);
    const nonceStore2 = new ServerNonceStore(new MemoryNonceBackend(), 60_000);
    const anomaly2 = new AnomalyEngine(new MemoryAnomalyStore());
    const kp2 = await generateKeypair();
    const sh2 = await hashSecret('race-guard-secret-2');
    const raceId2 = await registry2.registerDirect({ name: 'race-2', scope: 'read', mode: 'development', secretHash: sh2, pubJwk: kp2.pubJwk });
    const pair2 = await registry2.get(raceId2);
    if (pair2) { await store2.set({ ...pair2, failedSigs: 10 }); }
    const { signedData: sd2, signature: sig2 } = await buildSignedRequest(kp2.privateKey, raceId2, 'GET', '/api/data', sh2);
    const req2 = makeReqData({ pairId: raceId2, signedData: sd2, signature: sig2, method: 'GET', path: '/api/data' });
    const result2 = await verifyBPCRequest(req2, registry2, nonceStore2, anomaly2, { sigWindowMs: 60_000, lockoutCount: 10, enableShadowMode: true });
    expect(result2.ok).toBe(false);
    expect(result2.error).toBe('pair_locked');
    expect(result2.shadow).toBe(true);
  });
});

describe('@bpc/server — PairRegistry', () => {
  it('atomically consumes one pending approval under concurrent approvers', async () => {
    const store = new MemoryPairStore();
    const registry = new PairRegistry(store, 10, 10, true);
    const kp = await generateKeypair();
    const token = await registry.requestPairing({ name:'atomic', scope:'read', mode:'production', secretHash:await hashSecret('atomic-approval'), pubJwk:kp.pubJwk });
    const results = await Promise.allSettled([registry.approvePairing(token), registry.approvePairing(token)]);
    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    expect(await registry.listPending()).toHaveLength(0);
    expect(await registry.list()).toHaveLength(1);
  });

  it('serializes capacity, lifecycle updates, and successful-use claims', async () => {
    const store = new MemoryPairStore();
    const registry = new PairRegistry(store, 1, 10, true);
    const kp = await generateKeypair();
    const registration = (name:string) => ({ name, scope:'read' as const, mode:'production' as const, secretHash:'s'.repeat(43), pubJwk:kp.pubJwk, maxRequests:1 });
    const [a,b] = await Promise.all([registry.requestPairing(registration('a')),registry.requestPairing(registration('b'))]);
    const approvals = await Promise.allSettled([registry.approvePairing(a),registry.approvePairing(b)]);
    expect(approvals.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    const pairId = (approvals.find((result): result is PromiseFulfilledResult<string> => result.status === 'fulfilled'))!.value;
    await Promise.all([registry.updatePair(pairId,{name:'renamed'}),registry.updatePair(pairId,{scope:'admin'})]);
    expect(await registry.get(pairId)).toMatchObject({name:'renamed',scope:'admin'});
    expect((await Promise.all([registry.claimSuccessfulUse(pairId),registry.claimSuccessfulUse(pairId)])).filter(Boolean)).toHaveLength(1);
    expect(await registry.get(pairId)).toMatchObject({requests:1,status:'expired'});
    await Promise.all([registry.revoke(pairId),registry.updatePair(pairId,{name:'after-revoke'})]);
    expect(await registry.get(pairId)).toMatchObject({status:'revoked',name:'after-revoke'});
  });

  it('re-evaluates stale expiry and lock facts under the authority lock', async () => {
    const store=new MemoryPairStore(),registry=new PairRegistry(store,10,10,true),kp=await generateKeypair(),now=Date.now();
    const pairId=await registry.registerDirect({name:'stale-facts',scope:'read',mode:'production',secretHash:'s'.repeat(43),pubJwk:kp.pubJwk,expiresAt:now-1});
    await registry.updatePair(pairId,{expiresAt:now+60_000});
    expect(await registry.markExpired(pairId,now)).toBe(false);
    expect((await registry.get(pairId))?.status).toBe('active');
    const pair=await registry.get(pairId);await store.set({...pair!,failedSigs:10});
    await store.atomicMutate(pairId,(current)=>({...current,failedSigs:0}));
    expect(await registry.ensureLocked(pairId,10)).toBe(false);
    expect((await registry.get(pairId))?.status).toBe('active');
  });

  it('enforces approval and rotation predicates identically in the memory authority', async () => {
    const store=new MemoryPairStore(),kp=await generateKeypair(),registration={name:'policy',scope:'read' as const,mode:'production' as const,secretHash:'s'.repeat(43),pubJwk:kp.pubJwk,maxRequests:3,kind:'ghost' as const,canaryClass:'docs' as const};
    await store.setPending('policy-token',registration,1);
    await expect(store.approvePending('policy-token',{registration,requestedAt:1},{id:'bad-approval',...registration,name:'other',status:'active',created:2,lastActive:null,requests:0,failedSigs:0},10)).rejects.toThrow(/does not match|initial state/);
    expect(await store.getPending('policy-token')).toBeDefined();
    const old={id:'old-policy',...registration,status:'active' as const,created:2,lastActive:null,requests:0,failedSigs:0};await store.set(old);
    expect(await store.rotatePair(old,{...old,id:'bad-rotation',created:3,cumulativeFailures:0})).toBe(false);
    expect((await store.get(old.id))?.status).toBe('active');
  });

  it('requires an atomic store when production enforcement is requested', () => {
    const legacy = { get:async()=>undefined,set:async()=>{},delete:async()=>{},list:async()=>[],getPending:async()=>undefined,setPending:async()=>{},deletePending:async()=>{},listPending:async()=>[] };
    expect(() => new PairRegistry(legacy, 10, 10, true)).toThrow(/AtomicPairStore/);
  });

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
    // unknownRate=1 (30pts) + sigRate=1 (30pts) + replay=0 + expired=0 = 60
    // BPC-07 FIX: The old formula multiplied by 100 (producing 6000), causing any
    // server with 2+ unknown-pair probes to hit the 70-point attack threshold and
    // permanently 429-lock all clients. The correct score is 0-100, not 0-10000.
    expect(score).toBe(60);
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
