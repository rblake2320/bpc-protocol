import { describe, expect, it } from 'vitest';

import { ContractValidationError, type OutboxRecord } from '../src/ha-outbox-contract.js';
import { generateKeypair } from '@bpc/core';
import {
  Aes256GcmPairPayloadCodec,
  PgPairMutationApplier,
  bpcPairMutationSanitizer,
  type BpcPairMutation,
  type CanonicalPairRegistration,
  type CanonicalStoredPair,
} from '../src/pg-durable-pair-store.js';

const KEY = Buffer.alloc(32, 0x5a);
const KEY_ID = 'pair-key-1';
const codec = () => new Aes256GcmPairPayloadCodec(KEY_ID, (id) => {
  if (id !== KEY_ID) throw new Error('unknown key');
  return KEY;
});
const pair = (): CanonicalStoredPair => ({
  id: 'pair_1', name: 'Pair one', scope: 'read-write', mode: 'production',
  secretHash: 's'.repeat(43), pubJwk: { kty: 'EC', crv: 'P-256', x: 'x'.repeat(42)+'w', y: 'y'.repeat(42)+'w' },
  status: 'active', created: 1, lastActive: null, requests: 2, failedSigs: 1,
  cumulativeFailures: '1.25', firstFailureAt: 1, maxRequests: 100, kind: 'legitimate', expiresAt: 999,
});
const registration = (): CanonicalPairRegistration => {
  const p = pair();
  return { name: p.name, scope: p.scope, mode: p.mode, secretHash: p.secretHash, pubJwk: p.pubJwk, maxRequests: p.maxRequests, kind: p.kind };
};
const pairAad = (pairId = 'pair_1', streamId = 'bpc:pair:test/v1') => ({ domain:'bpc-pair-payload' as const, version:'1' as const, streamId, kind:'bpc.pair.set.v1' as const, pairId });
const pendingAad = (token = 'pending-1', requestedAt = 10, streamId = 'bpc:pair:test/v1') => ({ domain:'bpc-pair-payload' as const, version:'1' as const, streamId, kind:'bpc.pending.set.v1' as const, token, requestedAt });

describe('AES-256-GCM pair payload codec', () => {
  it('round-trips pair and pending payloads with identity-bound AAD', () => {
    const c = codec();
    const pAad = pairAad();
    const sealedPair = c.sealPair(pair(), pAad);
    expect(c.openPair(sealedPair, pAad)).toEqual(pair());
    const rAad = pendingAad();
    const sealedRegistration = c.sealRegistration(registration(), rAad);
    expect(c.openRegistration(sealedRegistration, rAad)).toEqual(registration());
  });

  it('never exposes the operational HMAC key or private JWK in a clean mutation', () => {
    const c = codec(); const p = pair();
    const sealed = c.sealPair(p, pairAad(p.id));
    const mutation = bpcPairMutationSanitizer.sanitize({ kind: 'bpc.pair.set.v1', pairId: p.id, sealed });
    const wire = JSON.stringify(mutation);
    expect(wire).not.toContain(p.secretHash);
    expect(wire).not.toContain('secretHash');
    expect(wire).not.toContain('"d"');
  });

  it('sanitizes compound approval and rotation mutations without clear authority material', () => {
    const c=codec(),p=pair(),r=registration(),streamId='bpc:pair:test/v1';
    const approval=bpcPairMutationSanitizer.sanitize({kind:'bpc.pair.approve.v1',token:'approval-1',requestedAt:10,expectedPending:c.sealRegistration(r,{domain:'bpc-pair-payload',version:'1',streamId,kind:'bpc.pair.approve.v1',token:'approval-1',requestedAt:10}),pairId:p.id,sealed:c.sealPair(p,{domain:'bpc-pair-payload',version:'1',streamId,kind:'bpc.pair.approve.v1',pairId:p.id})});
    const replacement={...p,id:'pair_2',requests:0,failedSigs:0,lastActive:null};
    const rotation=bpcPairMutationSanitizer.sanitize({kind:'bpc.pair.rotate.v1',oldPairId:p.id,expectedOld:c.sealPair(p,{domain:'bpc-pair-payload',version:'1',streamId,kind:'bpc.pair.rotate.v1',pairId:p.id}),newPairId:replacement.id,sealed:c.sealPair(replacement,{domain:'bpc-pair-payload',version:'1',streamId,kind:'bpc.pair.rotate.v1',pairId:replacement.id})});
    for(const mutation of [approval,rotation]){const wire=JSON.stringify(mutation);expect(wire).not.toContain(p.secretHash);expect(wire).not.toContain('secretHash');}
    expect(()=>bpcPairMutationSanitizer.sanitize({...approval,unexpected:true} as never)).toThrow(/unexpected field/);
    expect(()=>bpcPairMutationSanitizer.sanitize({...rotation,newPairId:p.id} as never)).toThrow(/identities/);
  });

  it('rejects a compound approval whose sealed pair does not match the pending registration before DML', async () => {
    const c=codec(),streamId='bpc:pair:test/v1',r=registration(),mismatched={...pair(),name:'different',requests:0,failedSigs:0,lastActive:null,cumulativeFailures:undefined,firstFailureAt:undefined};
    const mutation=bpcPairMutationSanitizer.sanitize({kind:'bpc.pair.approve.v1',token:'approval-1',requestedAt:10,expectedPending:c.sealRegistration(r,{domain:'bpc-pair-payload',version:'1',streamId,kind:'bpc.pair.approve.v1',token:'approval-1',requestedAt:10}),pairId:mismatched.id,sealed:c.sealPair(mismatched,{domain:'bpc-pair-payload',version:'1',streamId,kind:'bpc.pair.approve.v1',pairId:mismatched.id})});
    let queries=0;
    const record={contractVersion:'1',streamId,sourceEpoch:'e1',sequence:1,fenceToken:'0',opDigest:'0'.repeat(64),mutation} as OutboxRecord<BpcPairMutation>;
    await expect(new PgPairMutationApplier(streamId,{activeKeyId:KEY_ID,resolveKey:()=>KEY}).applyInTx({query:async()=>{queries++;return{rows:[],rowCount:0};}},record)).rejects.toThrow(/does not match pending/);
    expect(queries).toBe(0);
  });

  it('uses a fresh nonce and rejects wrong AAD, key, tag, keyId and identity', () => {
    const c = codec(), p = pair(), aad = pairAad(p.id);
    const a = c.sealPair(p, aad), b = c.sealPair(p, aad);
    expect(a.nonce).not.toBe(b.nonce); expect(a.ciphertext).not.toBe(b.ciphertext);
    expect(() => c.openPair(a, { ...aad, pairId: 'other' })).toThrow(/authentication|identity/);
    expect(() => new Aes256GcmPairPayloadCodec(KEY_ID, () => Buffer.alloc(32, 1)).openPair(a, aad)).toThrow(/authentication/);
    expect(() => c.openPair({ ...a, tag: Buffer.alloc(16, 2).toString('base64url') }, aad)).toThrow(/authentication/);
    expect(() => c.openPair({ ...a, keyId: 'unknown' }, aad)).toThrow(/authentication/);
    const aliasCodec = new Aes256GcmPairPayloadCodec(KEY_ID, (id) => {
      if (id !== KEY_ID && id !== 'pair-key-alias') throw new Error('unknown key');
      return KEY;
    });
    const aliasSealed = aliasCodec.sealPair(p, aad);
    expect(() => aliasCodec.openPair({ ...aliasSealed, keyId: 'pair-key-alias' }, aad)).toThrow(/authentication/);
    expect(() => c.openPair(a, pairAad(p.id, 'bpc:pair:other/v1'))).toThrow(/authentication/);
  });

  it('rejects private keys, accessors, proxies, extras and clear-payload mutation fields', () => {
    const c = codec(), p = pair();
    expect(() => c.sealPair({ ...p, pubJwk: { ...p.pubJwk, d: 'private' } } as unknown as CanonicalStoredPair, pairAad(p.id))).toThrow(/unexpected field|public P-256/);
    const accessor = Object.defineProperty({ ...p }, 'secretHash', { enumerable: true, get: () => p.secretHash });
    expect(() => c.sealPair(accessor as CanonicalStoredPair, pairAad(p.id))).toThrow(/data property/);
    expect(() => c.sealPair(new Proxy(p, {}) as CanonicalStoredPair, pairAad(p.id))).toThrow(/non-proxy/);
    expect(() => bpcPairMutationSanitizer.sanitize({ kind: 'bpc.pair.set.v1', pairId: p.id, sealed: c.sealPair(p, pairAad(p.id)), secretHash: p.secretHash } as never)).toThrow(/unexpected field/);
    let keyOpGetterFired = 0;
    const keyOps = Object.defineProperty([], '0', { enumerable: true, configurable: true, get: () => { keyOpGetterFired += 1; return 'verify'; } });
    Object.defineProperty(keyOps, 'length', { value: 1 });
    expect(() => c.sealPair({ ...p, pubJwk: { ...p.pubJwk, key_ops: keyOps } } as unknown as CanonicalStoredPair, pairAad(p.id))).toThrow(/data property|verify/);
    expect(keyOpGetterFired).toBe(0);
    let inheritedGetterFired = 0;
    Object.defineProperty(Object.prototype, 'name', { configurable: true, get: () => { inheritedGetterFired += 1; return 'polluted'; } });
    try {
      const missingName = { ...registration() } as Record<string, unknown>;
      delete missingName.name;
      expect(() => c.sealRegistration(missingName as unknown as CanonicalPairRegistration, pendingAad())).toThrow(/registration\.name/);
      expect(inheritedGetterFired).toBe(0);
    } finally {
      delete (Object.prototype as Record<string, unknown>).name;
    }
  });

  it('fails closed on malformed key lengths and payload encoding', () => {
    expect(() => new Aes256GcmPairPayloadCodec(KEY_ID, () => Buffer.alloc(31)).sealPair(pair(), pairAad())).toThrow(ContractValidationError);
    const c = codec(), sealed = c.sealPair(pair(), pairAad());
    expect(() => c.openPair({ ...sealed, nonce: 'bad' }, pairAad())).toThrow(/encoding/);
    expect(() => c.sealPair({ ...pair(), pubJwk:{...pair().pubJwk,x:'x'.repeat(43)} } as CanonicalStoredPair, pairAad())).toThrow(/public P-256/);
    const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const index=alphabet.indexOf(sealed.tag.at(-1)!);
    const alias=`${sealed.tag.slice(0,-1)}${alphabet[(index^1)]}`;
    expect(Buffer.from(alias,'base64url').equals(Buffer.from(sealed.tag,'base64url'))).toBe(true);
    expect(() => bpcPairMutationSanitizer.sanitize({kind:'bpc.pair.set.v1',pairId:pair().id,sealed:{...sealed,tag:alias}})).toThrow(/encoding/);
  });

  it('accepts and canonicalizes the repository core public-key export', async () => {
    const generated = await generateKeypair();
    const p = { ...pair(), pubJwk: generated.pubJwk } as CanonicalStoredPair;
    const aad = pairAad(p.id);
    const opened = codec().openPair(codec().sealPair(p, aad), aad);
    expect(opened.pubJwk).toEqual({ kty:'EC', crv:'P-256', x:generated.pubJwk.x, y:generated.pubJwk.y });
  });

});
