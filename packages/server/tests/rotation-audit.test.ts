/**
 * BPC — Rotation hardening + hash-chained audit log adversarial suite.
 *
 * Covers the fixes:
 *   ROT-01 atomicity (fail-closed), ROT-02 JWK binding, ROT-03 audit emit,
 *   ROT-04 key validation, and the tamper-evident audit chain
 *   (integrity / tamper / truncation, Memory + Pg).
 */

import { describe, it, expect } from 'vitest';
import {
  generateKeypair, signPayload, canonicalize, hashSecret, b64url,
} from '../../core/src/index.js';
import { PairRegistry } from '../src/registry.js';
import { MemoryPairStore } from '../src/memory-store.js';
import { handleRotation } from '../src/rotation.js';
import {
  MemoryAuditLog, PgAuditLog, GENESIS_HASH,
  type AuditEntry, type PgAuditPool,
} from '../src/audit.js';
import type { PairStore } from '../src/store.js';

// ── helpers ───────────────────────────────────────────────────────────────────
async function makePair(store: PairStore, name: string) {
  const registry = new PairRegistry(store);
  const kp = await generateKeypair();
  const sh = await hashSecret('ValidSecret1!@#$');
  const pairId = await registry.registerDirect({
    name, scope: 'read-write', mode: 'development', secretHash: sh, pubJwk: kp.pubJwk,
  });
  return { pairId, kp };
}

function buildRotation(oldPairId: string, newPubJwk: JsonWebKey, timestamp = Date.now()) {
  const payload = {
    new_pub_jwk_json: JSON.stringify(newPubJwk),
    old_pair_id: oldPairId,
    purpose: 'rotation',
    timestamp,
  };
  return { payload, timestamp };
}
async function signRotation(privKey: CryptoKey, payload: Record<string, unknown>) {
  const signature  = await signPayload(privKey, payload);
  const signedData = b64url(new TextEncoder().encode(canonicalize(payload)).buffer);
  return { signature, signedData };
}

// A minimal in-memory Postgres mock implementing the exact queries PgAuditLog issues.
class MockPgPool implements PgAuditPool {
  rows: Record<string, unknown>[] = [];
  async query(sql: string, params: unknown[] = []): Promise<{ rows: Record<string, unknown>[] }> {
    if (sql.includes('INSERT INTO bpc_audit')) {
      const seq = params[1] as number;
      if (this.rows.some(r => r['seq'] === seq)) { const e: any = new Error('dup'); e.code = '23505'; throw e; }
      const cols = ['id','seq','timestamp','action','severity','pair_id','error','ip','method','path','user_agent','request_id','detail','prev_hash','chain_hash'];
      const row: Record<string, unknown> = {};
      cols.forEach((c, i) => { row[c] = params[i] ?? null; });
      this.rows.push(row);
      return { rows: [] };
    }
    if (sql.includes('COUNT(*)')) return { rows: [{ n: this.rows.length }] };
    if (sql.includes('ORDER BY seq DESC LIMIT 1')) {
      const last = [...this.rows].sort((a, b) => Number(b['seq']) - Number(a['seq']))[0];
      return { rows: last ? [last] : [] };
    }
    if (sql.includes('ORDER BY seq ASC')) {
      return { rows: [...this.rows].sort((a, b) => Number(a['seq']) - Number(b['seq'])) };
    }
    return { rows: [] };
  }
}

// ── ROT: rotation hardening ────────────────────────────────────────────────────
describe('ROT — rotation hardening', () => {
  it('A1: cross-pair rotation forgery is rejected (sign A with B key)', async () => {
    const store = new MemoryPairStore();
    const a = await makePair(store, 'pair-A');
    const b = await makePair(store, 'pair-B');
    const newKp = await generateKeypair();

    const { payload, timestamp } = buildRotation(a.pairId, newKp.pubJwk);
    // Forge: sign pair A's rotation with pair B's private key.
    const { signature, signedData } = await signRotation(b.kp.privateKey, payload);

    const res = await handleRotation(
      { oldPairId: a.pairId, newPubJwk: newKp.pubJwk, signature, signedData, timestamp },
      store,
    );
    expect(res.ok).toBe(false);
    expect(res.error).toBe('invalid_signature');
    expect((await store.get(a.pairId))!.status).toBe('active'); // untouched
  });

  it('A2: mismatched new_pub_jwk binding is rejected', async () => {
    const store = new MemoryPairStore();
    const a = await makePair(store, 'pair-A');
    const signedNewKp = await generateKeypair(); // bound in payload
    const otherNewKp  = await generateKeypair(); // sent in request body

    const { payload, timestamp } = buildRotation(a.pairId, signedNewKp.pubJwk);
    const { signature, signedData } = await signRotation(a.kp.privateKey, payload);

    const res = await handleRotation(
      { oldPairId: a.pairId, newPubJwk: otherNewKp.pubJwk, signature, signedData, timestamp },
      store,
    );
    expect(res.ok).toBe(false);
    expect(res.error).toBe('payload_field_mismatch');
  });

  it('A3: malformed public JWK is rejected before signature work', async () => {
    const store = new MemoryPairStore();
    const a = await makePair(store, 'pair-A');
    const { payload, timestamp } = buildRotation(a.pairId, { kty: 'EC' } as JsonWebKey);
    const { signature, signedData } = await signRotation(a.kp.privateKey, payload);

    const res = await handleRotation(
      { oldPairId: a.pairId, newPubJwk: { kty: 'EC' } as JsonWebKey, signature, signedData, timestamp },
      store,
    );
    expect(res.ok).toBe(false);
    expect(res.error).toBe('invalid_request');
  });

  it('A4: fail-closed atomicity — new-pair persist failure leaves old DISABLED', async () => {
    const inner = new MemoryPairStore();
    let sets = 0;
    const failing: PairStore = {
      get: (id) => inner.get(id),
      set: async (p) => { sets++; if (sets === 2) throw new Error('disk full'); return inner.set(p); },
      delete: (id) => inner.delete(id),
      list: () => inner.list(),
      getPending: (t) => inner.getPending(t),
      setPending: (t, r, a) => inner.setPending(t, r, a),
      deletePending: (t) => inner.deletePending(t),
      listPending: () => inner.listPending(),
    };
    const a = await makePair(failing, 'pair-A'); // registerDirect = set #1
    sets = 0; // reset; rotation set#1 = old rotated, set#2 = new pair (throws)
    const newKp = await generateKeypair();
    const { payload, timestamp } = buildRotation(a.pairId, newKp.pubJwk);
    const { signature, signedData } = await signRotation(a.kp.privateKey, payload);

    const res = await handleRotation(
      { oldPairId: a.pairId, newPubJwk: newKp.pubJwk, signature, signedData, timestamp },
      failing,
    );
    expect(res.ok).toBe(false);
    expect(res.error).toBe('rotation_persist_failed');
    expect((await inner.get(a.pairId))!.status).toBe('rotated'); // fail-closed, not active
  });

  it('A5: successful rotation emits chained audit events (rotate + register)', async () => {
    const store = new MemoryPairStore();
    const audit = new MemoryAuditLog();
    const a = await makePair(store, 'pair-A');
    const newKp = await generateKeypair();
    const { payload, timestamp } = buildRotation(a.pairId, newKp.pubJwk);
    const { signature, signedData } = await signRotation(a.kp.privateKey, payload);

    const res = await handleRotation(
      { oldPairId: a.pairId, newPubJwk: newKp.pubJwk, signature, signedData, timestamp },
      store, 60_000, audit,
    );
    expect(res.ok).toBe(true);

    const all = audit.snapshot();
    expect(all.some(e => e.action === 'rotate' && e.pairId === a.pairId)).toBe(true);
    expect(all.some(e => e.action === 'register' && e.pairId === res.newPairId)).toBe(true);
    expect((await audit.verifyChain()).valid).toBe(true);
  });

  it('A6: rotation preserves ghost classification and request/expiry policy', async () => {
    const store=new MemoryPairStore(),registry=new PairRegistry(store,10,10,true),oldKey=await generateKeypair();
    const pairId=await registry.registerDirect({name:'ghost-capped',scope:'read',mode:'production',secretHash:await hashSecret('ghost-capped-secret'),pubJwk:oldKey.pubJwk,expiresAt:Date.now()+60_000,maxRequests:7,kind:'ghost',canaryClass:'registry_exfil'});
    const replacement=await generateKeypair(),{payload,timestamp}=buildRotation(pairId,replacement.pubJwk),{signature,signedData}=await signRotation(oldKey.privateKey,payload);
    const result=await handleRotation({oldPairId:pairId,newPubJwk:replacement.pubJwk,signature,signedData,timestamp},store);
    expect(result.ok).toBe(true);
    expect(await store.get(result.newPairId!)).toMatchObject({maxRequests:7,kind:'ghost',canaryClass:'registry_exfil'});
    expect((await store.get(result.newPairId!))?.expiresAt).toBe((await store.get(pairId))?.expiresAt);
  });
});

// ── AUD: hash-chained audit log ─────────────────────────────────────────────────
describe('AUD — tamper-evident audit chain', () => {
  async function seed(log: MemoryAuditLog, n: number) {
    for (let i = 0; i < n; i++) {
      await log.write({ action: 'verify_pass', pairId: `pair_${i % 3}`, ip: `10.0.0.${i}` });
    }
  }

  it('L1: a clean chain verifies and head reflects count', async () => {
    const log = new MemoryAuditLog();
    await seed(log, 5);
    const head = await log.head();
    expect(head.seq).toBe(5);
    expect(head.count).toBe(5);
    expect((await log.verifyChain()).valid).toBe(true);
  });

  it('L2: in-place tampering of a historical entry is detected', async () => {
    const log = new MemoryAuditLog();
    await seed(log, 5);
    // Mutate entry #3's action without recomputing its hash (attacker edit).
    const entries = (log as unknown as { entries: AuditEntry[] }).entries;
    entries[2].action = 'verify_fail';
    const res = await log.verifyChain();
    expect(res.valid).toBe(false);
    expect(res.brokenAtSeq).toBe(3);
  });

  it('L3: tail truncation/rollback is detected via the external anchor', async () => {
    const log = new MemoryAuditLog();
    await seed(log, 5);
    const anchor = await log.head();          // operator persists this
    await seed(log, 2);                         // 2 more writes (seq 6,7)
    // Attacker truncates back to the anchored length.
    (log as unknown as { entries: AuditEntry[] }).entries.length = 5;
    const res = await log.verifyChain({ expectedHead: await log.head() });
    // head() now reports seq 7 (counter survives), entries only go to 5 → mismatch
    expect(res.valid).toBe(false);
    expect(anchor.seq).toBe(5);
  });

  it('L4: PgAuditLog (mock) builds and verifies an identical chain', async () => {
    const pool = new MockPgPool();
    const log = new PgAuditLog(pool);
    await log.write({ action: 'register', pairId: 'pair_x' });
    await log.write({ action: 'verify_pass', pairId: 'pair_x' });
    await log.write({ action: 'rotate', pairId: 'pair_x', detail: '{"newPairId":"pair_y"}' });

    expect(pool.rows.length).toBe(3);
    expect(pool.rows[0]['prev_hash']).toBe(GENESIS_HASH);
    expect((await log.verifyChain()).valid).toBe(true);

    // Tamper a stored row → verification fails.
    pool.rows[1]['action'] = 'verify_fail';
    expect((await log.verifyChain()).valid).toBe(false);
  });
});
