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
  type MutationApplier,
  type OutboxTransport,
  type PgExecutor,
  type PgTransactor,
} from '../src/ha-outbox-pg.js';

/**
 * Snapshot-based in-memory transactional store modelling the EXACT queries the
 * impl issues. transaction() runs on a CLONE and commits only on success; a
 * throw discards it (ROLLBACK / crash). Proves single-authority LOGIC + crash-
 * atomicity; the real two-node PostgreSQL+Redis drill is separate (#16 OPEN).
 */
interface Row { stream_id: string; source_epoch: string; sequence: number; fence_token: string; op_digest: string; mutation: unknown; published_at: string | null; acked_at: string | null }
interface Applied { stream_id: string; source_epoch: string; sequence: number; op_digest: string }
interface State { fence: Map<string, bigint>; checkpoint: Map<string, { source_epoch: string; sequence: number; last_digest: string }>; rows: Row[]; applied: Applied[] }

class MemoryPg implements PgTransactor {
  state: State = { fence: new Map(), checkpoint: new Map(), rows: [], applied: [] };
  crashBeforeCommit = false;
  private clone(s: State): State {
    return { fence: new Map(s.fence), checkpoint: new Map([...s.checkpoint].map(([k, v]) => [k, { ...v }])), rows: s.rows.map((r) => ({ ...r })), applied: s.applied.map((a) => ({ ...a })) };
  }
  async transaction<T>(fn: (exec: PgExecutor) => Promise<T>): Promise<T> {
    const work = this.clone(this.state);
    const result = await fn(makeExec(work));
    if (this.crashBeforeCommit) { this.crashBeforeCommit = false; throw new Error('crash before commit'); }
    this.state = work;
    return result;
  }
  provision(streamId: string, epoch: string): void { this.state.fence.set(streamId, 0n); this.state.checkpoint.set(streamId, { source_epoch: epoch, sequence: 0, last_digest: '' }); }
  seq(streamId: string): number { return this.state.checkpoint.get(streamId)!.sequence; }
  rowCount(streamId: string): number { return this.state.rows.filter((r) => r.stream_id === streamId).length; }
  setFence(streamId: string, t: bigint): void { this.state.fence.set(streamId, t); }
  deleteFence(streamId: string): void { this.state.fence.delete(streamId); }
}

function makeExec(s: State): PgExecutor {
  return {
    async query(sql: string, params: unknown[] = []) {
      const P = params as string[];
      if (sql.includes('FROM ha_outbox_fence') && sql.includes('SELECT fence_token')) { const t = s.fence.get(P[0]); return { rows: t === undefined ? [] : [{ fence_token: t.toString() }] }; }
      if (sql.includes('INSERT INTO ha_outbox_fence')) { const cur = s.fence.get(P[0]) ?? 0n; const n = cur + 1n; s.fence.set(P[0], n); return { rows: [{ fence_token: n.toString() }] }; }
      if (sql.includes('count(*)')) return { rows: [{ n: s.rows.filter((r) => r.stream_id === P[0] && r.acked_at === null).length }] };
      if (sql.includes('SELECT source_epoch, sequence FROM ha_outbox_checkpoint')) { const c = s.checkpoint.get(P[0]); return { rows: c ? [{ source_epoch: c.source_epoch, sequence: c.sequence }] : [] }; }
      if (sql.includes('INSERT INTO ha_outbox_rows')) { s.rows.push({ stream_id: P[0], source_epoch: P[1], sequence: Number(P[2]), fence_token: P[3], op_digest: P[4], mutation: JSON.parse(P[5]), published_at: null, acked_at: null }); return { rows: [] }; }
      if (sql.includes('UPDATE ha_outbox_checkpoint SET sequence = $2 WHERE')) { s.checkpoint.get(P[0])!.sequence = Number(P[1]); return { rows: [] }; }
      if (sql.includes('UPDATE ha_outbox_checkpoint SET sequence=$2, last_digest=$3')) { const c = s.checkpoint.get(P[0])!; c.sequence = Number(P[1]); c.last_digest = P[2]; return { rows: [] }; }
      if (sql.includes('INSERT INTO ha_outbox_applied')) { s.applied.push({ stream_id: P[0], source_epoch: P[1], sequence: Number(P[2]), op_digest: P[3] }); return { rows: [] }; }
      if (sql.includes('FROM ha_outbox_applied')) { const a = s.applied.find((x) => x.stream_id === P[0] && x.source_epoch === P[1] && x.sequence === Number(P[2])); return { rows: a ? [{ op_digest: a.op_digest }] : [] }; }
      if (sql.includes('FROM ha_outbox_rows') && sql.includes('acked_at IS NULL ORDER BY sequence')) { return { rows: s.rows.filter((r) => r.stream_id === P[0] && r.acked_at === null).sort((a, b) => a.sequence - b.sequence).map((r) => ({ source_epoch: r.source_epoch, sequence: r.sequence, fence_token: r.fence_token, op_digest: r.op_digest, mutation: r.mutation })) }; }
      if (sql.includes('UPDATE ha_outbox_rows SET published_at')) { const r = s.rows.find((x) => x.stream_id === P[0] && x.source_epoch === P[1] && x.sequence === Number(P[2]))!; r.published_at = 'now'; r.acked_at = 'now'; return { rows: [] }; }
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
const okAck = (r: OutboxRecord<unknown>): AckReceipt => ({ streamId: r.streamId, sourceEpoch: r.sourceEpoch, sequence: r.sequence, opDigest: r.opDigest });
const dig = (streamId: string, sourceEpoch: string, sequence: number, fenceToken: string, m: Clean) =>
  canonicalOpDigest<Clean>({ streamId, sourceEpoch, sequence, fenceToken, mutation: m as SanitizedMutation<Clean> });

describe('PgDurableOutbox / receiver / publisher / fence (#16, adversarial)', () => {
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
    expect(db.rowCount(SID)).toBe(0); expect(db.seq(SID)).toBe(0);
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

  // ── receiver ──
  const rcvFor = (sid: string) => new PgReceiverCheckpoint<Clean>(sid, sanitizer, applier);
  const apply = (rcv: PgReceiverCheckpoint<Clean>, rec: OutboxRecord<Clean>) => db.transaction((e) => rcv.verifyAndApplyInTx(createBoundTx(e), rec));
  const mk = (sid: string, seq: number, m: Clean, fence = '0'): OutboxRecord<Clean> => ({ contractVersion: '1', streamId: sid, sourceEpoch: 'e1', sequence: seq, fenceToken: fence, opDigest: dig(sid, 'e1', seq, fence, m), mutation: m as SanitizedMutation<Clean> });

  it('#1 receiver recomputes digest — a tampered payload with preserved opDigest is reject-fork', async () => {
    db.provision('r1/v1', 'e1'); const rcv = rcvFor('r1/v1');
    const good = mk('r1/v1', 1, { pairId: 'p1' });
    const tampered: OutboxRecord<Clean> = { ...good, mutation: { pairId: 'HACKED' } as SanitizedMutation<Clean> }; // opDigest kept
    expect(await apply(rcv, tampered)).toBe('reject-fork');
    expect(applied.length).toBe(0);
  });
  it('#2 receiver fence: exact equality — FUTURE token and MISSING row both reject-fence', async () => {
    db.provision('r2/v1', 'e1'); const rcv = rcvFor('r2/v1');
    db.setFence('r2/v1', 3n);
    expect(await apply(rcv, mk('r2/v1', 1, { pairId: 'p1' }, '5'))).toBe('reject-fence'); // future
    expect(await apply(rcv, mk('r2/v1', 1, { pairId: 'p1' }, '2'))).toBe('reject-fence'); // stale
    db.deleteFence('r2/v1');
    expect(await apply(rcv, mk('r2/v1', 1, { pairId: 'p1' }, '0'))).toBe('reject-fence'); // missing row
  });
  it('#3 durable receiver history: older duplicate/fork survive (not from source table)', async () => {
    db.provision('r3/v1', 'e1'); const rcv = rcvFor('r3/v1');
    expect(await apply(rcv, mk('r3/v1', 1, { pairId: 'p1' }))).toBe('applied');
    expect(await apply(rcv, mk('r3/v1', 2, { pairId: 'p2' }))).toBe('applied');
    // older duplicate (seq1, same digest) → idempotent from applied-history
    expect(await apply(rcv, mk('r3/v1', 1, { pairId: 'p1' }))).toBe('duplicate-ok');
    // older FORK (seq1, different content → different digest) → reject-fork
    const fork = mk('r3/v1', 1, { pairId: 'DIFFERENT' });
    expect(await apply(rcv, fork)).toBe('reject-fork');
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
    expect(db.state.checkpoint.get('r5/v1')!.sequence).toBe(0);
    expect(db.state.applied.length).toBe(0);
  });

  // ── publisher ──
  const pubFor = (t: OutboxTransport) => new PgDurablePublisher<Clean>(db, SID, t, 'quarantine', sanitizer);
  it('#4 publisher only ACKs on a matching record-bound receipt; a fake/mismatched ACK is not acked', async () => {
    await outbox.withOutboxTx((tx) => outbox.appendInTx(tx, { streamId: SID, rawMutation: { pairId: 'p1' }, fenceToken: 0n }));
    const badPub = pubFor({ async deliverAndAwaitAck(r) { return { ...okAck(r), opDigest: 'f'.repeat(64) }; } }); // wrong digest receipt
    await expect(badPub.drainOnce()).rejects.toThrow(/ACK receipt/);
    expect(db.state.rows[0].acked_at).toBeNull();
    const goodPub = pubFor({ async deliverAndAwaitAck(r) { return okAck(r); } });
    expect((await goodPub.drainOnce()).acked).toBe(1);
    expect(db.state.rows[0].acked_at).not.toBeNull();
  });
  it('#4 transport failure leaves row unacked (at-least-once retry)', async () => {
    await outbox.withOutboxTx((tx) => outbox.appendInTx(tx, { streamId: SID, rawMutation: { pairId: 'p1' }, fenceToken: 0n }));
    let fail = true;
    const pub = pubFor({ async deliverAndAwaitAck(r) { if (fail) throw new Error('transport down'); return okAck(r); } });
    await expect(pub.drainOnce()).rejects.toThrow('transport');
    expect(db.state.rows[0].acked_at).toBeNull();
    fail = false; expect((await pub.drainOnce()).acked).toBe(1);
  });
  it('#5 publisher fails closed on a corrupted stored row (digest mismatch)', async () => {
    await outbox.withOutboxTx((tx) => outbox.appendInTx(tx, { streamId: SID, rawMutation: { pairId: 'p1' }, fenceToken: 0n }));
    db.state.rows[0].mutation = { pairId: 'TAMPERED' }; // corrupt the stored payload, keep op_digest
    const pub = pubFor({ async deliverAndAwaitAck(r) { return okAck(r); } });
    await expect(pub.drainOnce()).rejects.toThrow(/corrupted outbox row/);
    expect(db.state.rows[0].acked_at).toBeNull();
  });

  it('#6 unsafe DB bigint sequence is rejected (no silent Number() truncation)', async () => {
    db.provision('r6/v1', 'e1');
    db.state.checkpoint.get('r6/v1')!.sequence = Number.MAX_SAFE_INTEGER + 10; // simulate an unsafe value
    const rcv = rcvFor('r6/v1');
    await expect(apply(rcv, mk('r6/v1', 1, { pairId: 'p1' }))).rejects.toBeInstanceOf(ContractValidationError);
  });

  it('promotion fence is monotonic + persisted', async () => {
    const fence = new PgPromotionFence(db);
    const t1 = await fence.acquire('f/v1'); const t2 = await fence.acquire('f/v1');
    expect(t2).toBeGreaterThan(t1); expect(await fence.current('f/v1')).toBe(t2);
  });
});
