import { describe, expect, it, beforeEach } from 'vitest';

import {
  ContractValidationError,
  OutboxBackpressureError,
  StaleFenceError,
  canonicalOpDigest,
  type MutationSanitizer,
  type OutboxRecord,
  type SanitizedMutation,
} from '../src/ha-outbox-contract.js';
import {
  PgDurableOutbox,
  PgDurablePublisher,
  PgPromotionFence,
  PgReceiverCheckpoint,
  createBoundTx,
  type AckReceipt,
  type AckReceiptVerifier,
  type MutationApplier,
  type OutboxTransport,
  type PgExecutor,
  type PgTransactor,
} from '../src/ha-outbox-pg.js';

/**
 * Snapshot-based in-memory transactional store for LOGIC only. transaction()
 * runs on a CLONE and commits on success; a throw discards it (ROLLBACK/crash).
 * It reports SERIALIZABLE and a rowCount so the impl's runtime invariants
 * (isolation assertion, exactly-1 write effects) are exercised. It CANNOT prove
 * lock/lease/concurrency behavior — that is ha-outbox-pg.realpg.test.ts.
 */
interface Row { stream_id: string; source_epoch: string; sequence: number; fence_token: string; op_digest: string; mutation: unknown; claim_token: string | null; claim_until: number | null; acked_at: string | null }
interface Applied { stream_id: string; source_epoch: string; sequence: number; op_digest: string }
interface Cp { source_epoch: string; sequence: number; last_digest: string }
interface State { fence: Map<string, bigint>; src: Map<string, Cp>; rcv: Map<string, Cp>; rows: Row[]; applied: Applied[] }

let CLOCK = 1000;
class MemoryPg implements PgTransactor {
  isolation = 'serializable';
  state: State = { fence: new Map(), src: new Map(), rcv: new Map(), rows: [], applied: [] };
  crashBeforeCommit = false;
  private clone(s: State): State {
    return { fence: new Map(s.fence), src: new Map([...s.src].map(([k, v]) => [k, { ...v }])), rcv: new Map([...s.rcv].map(([k, v]) => [k, { ...v }])), rows: s.rows.map((r) => ({ ...r })), applied: s.applied.map((a) => ({ ...a })) };
  }
  async transaction<T>(fn: (exec: PgExecutor) => Promise<T>): Promise<T> {
    const work = this.clone(this.state);
    const result = await fn(makeExec(work, this.isolation));
    if (this.crashBeforeCommit) { this.crashBeforeCommit = false; throw new Error('crash before commit'); }
    this.state = work;
    return result;
  }
  provision(streamId: string, epoch: string): void { this.state.fence.set(streamId, 0n); this.state.src.set(streamId, { source_epoch: epoch, sequence: 0, last_digest: '' }); this.state.rcv.set(streamId, { source_epoch: epoch, sequence: 0, last_digest: '' }); }
  srcSeq(streamId: string): number { return this.state.src.get(streamId)!.sequence; }
  rcvSeq(streamId: string): number { return this.state.rcv.get(streamId)!.sequence; }
  rowCount(streamId: string): number { return this.state.rows.filter((r) => r.stream_id === streamId).length; }
  setFence(streamId: string, t: bigint): void { this.state.fence.set(streamId, t); }
  deleteFence(streamId: string): void { this.state.fence.delete(streamId); }
}

function makeExec(s: State, isolation: string): PgExecutor {
  return {
    async query(sql: string, params: unknown[] = []) {
      const P = params as string[];
      const out = (rows: Record<string, unknown>[]) => ({ rows, rowCount: rows.length });
      if (sql.includes('SHOW transaction_isolation')) return out([{ transaction_isolation: isolation }]);
      if (sql.includes('FROM ha_outbox_fence') && sql.includes('SELECT fence_token')) { const t = s.fence.get(P[0]); return out(t === undefined ? [] : [{ fence_token: t.toString() }]); }
      if (sql.includes('INSERT INTO ha_outbox_fence')) { const cur = s.fence.get(P[0]) ?? 0n; const n = cur + 1n; s.fence.set(P[0], n); return out([{ fence_token: n.toString() }]); }
      if (sql.includes('count(*)')) return out([{ n: String(s.rows.filter((r) => r.stream_id === P[0] && r.acked_at === null).length) }]);
      if (sql.includes('FROM ha_outbox_source_checkpoint')) { const c = s.src.get(P[0]); return out(c ? [{ source_epoch: c.source_epoch, sequence: c.sequence }] : []); }
      if (sql.includes('FROM ha_outbox_receiver_checkpoint')) { const c = s.rcv.get(P[0]); return out(c ? [{ source_epoch: c.source_epoch, sequence: c.sequence }] : []); }
      if (sql.includes('INSERT INTO ha_outbox_rows')) { s.rows.push({ stream_id: P[0], source_epoch: P[1], sequence: Number(P[2]), fence_token: P[3], op_digest: P[4], mutation: JSON.parse(P[5]), claim_token: null, claim_until: null, acked_at: null }); return out([{}]); }
      if (sql.includes('UPDATE ha_outbox_source_checkpoint SET sequence')) { s.src.get(P[0])!.sequence = Number(P[1]); return out([{}]); }
      if (sql.includes('UPDATE ha_outbox_receiver_checkpoint SET sequence')) { const c = s.rcv.get(P[0])!; c.sequence = Number(P[1]); c.last_digest = P[2]; return out([{}]); }
      if (sql.includes('INSERT INTO ha_outbox_applied')) { s.applied.push({ stream_id: P[0], source_epoch: P[1], sequence: Number(P[2]), op_digest: P[3] }); return out([{}]); }
      if (sql.includes('FROM ha_outbox_applied')) { const a = s.applied.find((x) => x.stream_id === P[0] && x.source_epoch === P[1] && x.sequence === Number(P[2])); return out(a ? [{ op_digest: a.op_digest }] : []); }
      if (sql.includes('UPDATE ha_outbox_rows r') && sql.includes('claim_token')) {
        const now = CLOCK++;
        const claimable = s.rows.filter((r) => r.stream_id === P[0] && r.acked_at === null && (r.claim_until === null || r.claim_until < now)).sort((a, b) => a.sequence - b.sequence).slice(0, Number(P[1]));
        for (const r of claimable) { r.claim_token = P[2]; r.claim_until = now + Number(P[3]); }
        return out(claimable.map((r) => ({ source_epoch: r.source_epoch, sequence: r.sequence, fence_token: r.fence_token, op_digest: r.op_digest, mutation: r.mutation })));
      }
      if (sql.includes('UPDATE ha_outbox_rows SET published_at')) { const r = s.rows.find((x) => x.stream_id === P[0] && x.source_epoch === P[1] && x.sequence === Number(P[2]) && x.acked_at === null && x.claim_token === P[3] && x.op_digest === P[4]); if (!r) return out([]); r.acked_at = 'now'; r.claim_token = null; return out([{}]); }
      throw new Error('unhandled SQL in fake: ' + sql.slice(0, 60));
    },
  };
}

interface Raw { pairId: string; secret?: string }
interface Clean { pairId: string }
const sanitizer: MutationSanitizer<Raw, Clean> = {
  sanitize(raw) { if (typeof raw.pairId !== 'string') throw new ContractValidationError('bad'); return { pairId: raw.pairId } as SanitizedMutation<Clean>; },
  assertSanitized(c): asserts c is SanitizedMutation<Clean> { if (!c || typeof c !== 'object' || 'secret' in (c as object)) throw new ContractValidationError('unsanitized'); },
};
const applied: string[] = [];
const applier: MutationApplier<Clean> = { async applyInTx(_e, r) { applied.push(`${r.sequence}:${(r.mutation as Clean).pairId}`); } };
const SID = 'bpc:pair:default/v1';
// A real (if simple) signature scheme for the fake: signature binds keyId to the
// record digest; the verifier recomputes and rejects any mismatch/forgery.
const RECEIVER_ID = 'receiver-A', KEY_ID = 'k1';
const sign = (record: OutboxRecord<unknown>) => `${KEY_ID}:${record.opDigest}`;
const okAck = (r: OutboxRecord<unknown>): AckReceipt => ({ streamId: r.streamId, sourceEpoch: r.sourceEpoch, sequence: r.sequence, opDigest: r.opDigest, receiverId: RECEIVER_ID, keyId: KEY_ID, issuedAt: 'now', signature: sign(r) });
const verifier: AckReceiptVerifier = {
  async verify(receipt, record) {
    if (receipt.receiverId !== RECEIVER_ID || receipt.keyId !== KEY_ID) throw new ContractValidationError('unknown/unauthorized receiver');
    if (receipt.signature !== sign(record)) throw new ContractValidationError('bad ACK signature (forged/unsigned)');
  },
};
const dig = (streamId: string, sourceEpoch: string, sequence: number, fenceToken: string, m: Clean) =>
  canonicalOpDigest<Clean>({ streamId, sourceEpoch, sequence, fenceToken, mutation: m as SanitizedMutation<Clean> });

describe('PgDurableOutbox / receiver / publisher / fence (#16, adversarial LOGIC)', () => {
  let db: MemoryPg; let outbox: PgDurableOutbox<Raw, Clean>;
  beforeEach(() => { db = new MemoryPg(); db.provision(SID, 'e1'); applied.length = 0;
    outbox = new PgDurableOutbox(db, { streamId: SID, sanitizer, maxPendingRows: 3, backpressure: 'fail-authoritative-mutation' }); });

  it('append allocates seq>=1, binds fence, sanitizes; atomic', async () => {
    const h = await outbox.withOutboxTx((tx) => outbox.appendInTx(tx, { streamId: SID, rawMutation: { pairId: 'p1', secret: 'X' }, fenceToken: 0n }));
    expect(h.sequence).toBe(1); expect(h.fenceToken).toBe('0'); expect(db.rowCount(SID)).toBe(1);
    expect('secret' in (db.state.rows[0].mutation as object)).toBe(false);
  });
  it('CRASH before commit rolls back mutation + sequence', async () => {
    db.crashBeforeCommit = true;
    await expect(outbox.withOutboxTx((tx) => outbox.appendInTx(tx, { streamId: SID, rawMutation: { pairId: 'p1' }, fenceToken: 0n }))).rejects.toThrow('crash');
    expect(db.rowCount(SID)).toBe(0); expect(db.srcSeq(SID)).toBe(0);
  });
  it('append stale fence fails closed; MISSING fence row fails closed', async () => {
    db.setFence(SID, 5n);
    await expect(outbox.withOutboxTx((tx) => outbox.appendInTx(tx, { streamId: SID, rawMutation: { pairId: 'p1' }, fenceToken: 4n }))).rejects.toBeInstanceOf(StaleFenceError);
    db.deleteFence(SID);
    await expect(outbox.withOutboxTx((tx) => outbox.appendInTx(tx, { streamId: SID, rawMutation: { pairId: 'p1' }, fenceToken: 0n }))).rejects.toBeInstanceOf(ContractValidationError);
  });
  it('backpressure fails closed, never sheds', async () => {
    for (let i = 0; i < 3; i++) await outbox.withOutboxTx((tx) => outbox.appendInTx(tx, { streamId: SID, rawMutation: { pairId: 'p' + i }, fenceToken: 0n }));
    await expect(outbox.withOutboxTx((tx) => outbox.appendInTx(tx, { streamId: SID, rawMutation: { pairId: 'p4' }, fenceToken: 0n }))).rejects.toBeInstanceOf(OutboxBackpressureError);
    expect(db.rowCount(SID)).toBe(3);
  });
  it('(HIGH6) append rejects an unsafe stored source sequence instead of Number()-truncating', async () => {
    db.state.src.get(SID)!.sequence = Number.MAX_SAFE_INTEGER + 5;
    await expect(outbox.withOutboxTx((tx) => outbox.appendInTx(tx, { streamId: SID, rawMutation: { pairId: 'p1' }, fenceToken: 0n }))).rejects.toBeInstanceOf(ContractValidationError);
  });
  it('(HIGH4) a non-serializable transactor is rejected at the critical tx entry', async () => {
    db.isolation = 'read committed';
    await expect(outbox.withOutboxTx((tx) => outbox.appendInTx(tx, { streamId: SID, rawMutation: { pairId: 'p1' }, fenceToken: 0n }))).rejects.toThrow(/SERIALIZABLE/);
  });

  // ── receiver ──
  const rcvFor = (sid: string) => new PgReceiverCheckpoint<Clean>(sid, sanitizer, applier);
  const apply = (rcv: PgReceiverCheckpoint<Clean>, rec: OutboxRecord<Clean>) => db.transaction((e) => rcv.verifyAndApplyInTx(createBoundTx(e), rec));
  const mk = (sid: string, seq: number, m: Clean, fence = '0'): OutboxRecord<Clean> => ({ contractVersion: '1', streamId: sid, sourceEpoch: 'e1', sequence: seq, fenceToken: fence, opDigest: dig(sid, 'e1', seq, fence, m), mutation: m as SanitizedMutation<Clean> });

  it('#1 tampered payload with preserved opDigest is reject-fork', async () => {
    db.provision('r1/v1', 'e1'); const rcv = rcvFor('r1/v1');
    const good = mk('r1/v1', 1, { pairId: 'p1' });
    const tampered: OutboxRecord<Clean> = { ...good, mutation: { pairId: 'HACKED' } as SanitizedMutation<Clean> };
    expect(await apply(rcv, tampered)).toBe('reject-fork');
    expect(applied.length).toBe(0);
  });
  it('#2 fence exact equality — FUTURE token, STALE token, MISSING row all reject-fence', async () => {
    db.provision('r2/v1', 'e1'); const rcv = rcvFor('r2/v1');
    db.setFence('r2/v1', 3n);
    expect(await apply(rcv, mk('r2/v1', 1, { pairId: 'p1' }, '5'))).toBe('reject-fence');
    expect(await apply(rcv, mk('r2/v1', 1, { pairId: 'p1' }, '2'))).toBe('reject-fence');
    db.deleteFence('r2/v1');
    expect(await apply(rcv, mk('r2/v1', 1, { pairId: 'p1' }, '0'))).toBe('reject-fence');
  });
  it('#3 durable receiver history: older duplicate ok + older fork rejected', async () => {
    db.provision('r3/v1', 'e1'); const rcv = rcvFor('r3/v1');
    expect(await apply(rcv, mk('r3/v1', 1, { pairId: 'p1' }))).toBe('applied');
    expect(await apply(rcv, mk('r3/v1', 2, { pairId: 'p2' }))).toBe('applied');
    expect(await apply(rcv, mk('r3/v1', 1, { pairId: 'p1' }))).toBe('duplicate-ok');
    expect(await apply(rcv, mk('r3/v1', 1, { pairId: 'DIFFERENT' }))).toBe('reject-fork');
  });
  it('(HIGH3) receiver checkpoint is INDEPENDENT of the source allocator checkpoint', async () => {
    db.provision('r7/v1', 'e1'); const rcv = rcvFor('r7/v1');
    db.state.src.get('r7/v1')!.sequence = 99; // source far ahead
    expect(await apply(rcv, mk('r7/v1', 1, { pairId: 'p1' }))).toBe('applied');
    expect(db.rcvSeq('r7/v1')).toBe(1);
    expect(db.srcSeq('r7/v1')).toBe(99);
  });
  it('receiver gap / stale-without-history / epoch', async () => {
    db.provision('r4/v1', 'e1'); const rcv = rcvFor('r4/v1');
    expect(await apply(rcv, mk('r4/v1', 1, { pairId: 'p1' }))).toBe('applied');
    expect(await apply(rcv, mk('r4/v1', 3, { pairId: 'p3' }))).toBe('reject-gap');
    const otherEpoch: OutboxRecord<Clean> = { ...mk('r4/v1', 2, { pairId: 'p2' }), sourceEpoch: 'e9', opDigest: dig('r4/v1', 'e9', 2, '0', { pairId: 'p2' }) };
    expect(await apply(rcv, otherEpoch)).toBe('reject-epoch');
  });
  it('receiver CRASH between apply and checkpoint leaves checkpoint + history unchanged', async () => {
    db.provision('r5/v1', 'e1'); const rcv = rcvFor('r5/v1');
    db.crashBeforeCommit = true;
    await expect(apply(rcv, mk('r5/v1', 1, { pairId: 'p1' }))).rejects.toThrow('crash');
    expect(db.rcvSeq('r5/v1')).toBe(0);
    expect(db.state.applied.length).toBe(0);
  });

  // ── publisher (claim-lease logic; concurrency proven in realpg suite) ──
  const pubFor = (t: OutboxTransport, v: AckReceiptVerifier = verifier) => new PgDurablePublisher<Clean>(db, SID, t, 'quarantine', sanitizer, v, { batchSize: 64, leaseMs: 30_000 });
  const seed = async (n: number) => { for (let i = 0; i < n; i++) await outbox.withOutboxTx((tx) => outbox.appendInTx(tx, { streamId: SID, rawMutation: { pairId: 'p' + i }, fenceToken: 0n })); };

  it('#4 delivers + acks each row via a record-bound verified receipt', async () => {
    await seed(2);
    const pub = pubFor({ async deliverAndAwaitAck(r) { return okAck(r); } });
    expect(await pub.drainOnce()).toEqual({ published: 2, acked: 2 });
    expect(db.state.rows.every((r) => r.acked_at !== null)).toBe(true);
  });
  it('#4 / HIGH2 a field-perfect but UNSIGNED/forged receipt is denied — row not acked', async () => {
    await seed(1);
    const forged = pubFor({ async deliverAndAwaitAck(r) { return { ...okAck(r), signature: 'FORGED' }; } });
    await expect(forged.drainOnce()).rejects.toThrow(/signature|forged/i);
    expect(db.state.rows[0].acked_at).toBeNull();
  });
  it('#4 a mismatched-tuple receipt is denied even if it passes signature verify — row not acked', async () => {
    await seed(1);
    const passAll: AckReceiptVerifier = { async verify() { /* passes so the record-bound echo check is what must reject */ } };
    const bad = pubFor({ async deliverAndAwaitAck(r) { return { ...okAck(r), opDigest: 'f'.repeat(64) }; } }, passAll);
    await expect(bad.drainOnce()).rejects.toThrow(/does not match/);
    expect(db.state.rows[0].acked_at).toBeNull();
  });
  it('#4 transport failure leaves row unacked (lease-expiry retry)', async () => {
    await seed(1);
    let fail = true;
    const pub = pubFor({ async deliverAndAwaitAck(r) { if (fail) throw new Error('transport down'); return okAck(r); } });
    await expect(pub.drainOnce()).rejects.toThrow('transport');
    expect(db.state.rows[0].acked_at).toBeNull();
    fail = false; db.state.rows[0].claim_until = 0; // lease expired → reclaimable
    expect((await pub.drainOnce()).acked).toBe(1);
  });
  it('#5 publisher fails closed on a corrupted stored row (digest mismatch)', async () => {
    await seed(1);
    db.state.rows[0].mutation = { pairId: 'TAMPERED' };
    const pub = pubFor({ async deliverAndAwaitAck(r) { return okAck(r); } });
    await expect(pub.drainOnce()).rejects.toThrow(/corrupted outbox row/);
    expect(db.state.rows[0].acked_at).toBeNull();
  });

  it('(#6/MED8) unsafe DB bigint sequence is a ContractValidationError (no native leak, no truncation)', async () => {
    db.provision('r6/v1', 'e1');
    db.state.rcv.get('r6/v1')!.sequence = Number.MAX_SAFE_INTEGER + 10;
    const rcv = rcvFor('r6/v1');
    await expect(apply(rcv, mk('r6/v1', 1, { pairId: 'p1' }))).rejects.toBeInstanceOf(ContractValidationError);
  });

  it('promotion fence is monotonic + persisted', async () => {
    const fence = new PgPromotionFence(db);
    const t1 = await fence.acquire('f/v1'); const t2 = await fence.acquire('f/v1');
    expect(t2).toBeGreaterThan(t1); expect(await fence.current('f/v1')).toBe(t2);
  });
});
