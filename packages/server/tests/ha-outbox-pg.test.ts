import { describe, expect, it, beforeEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  ContractValidationError,
  OutboxBackpressureError,
  StaleFenceError,
  canonicalOpDigest,
  type MutationSanitizer,
  type OutboxRecord,
  type ReceiverDecision,
  type SanitizedMutation,
} from '../src/ha-outbox-contract.js';
import {
  HA_OUTBOX_SCHEMA_VERSION,
  PgDurableOutbox,
  PgDurablePublisher,
  PgPromotionFence,
  PgReceiverCheckpoint,
  assertSchemaVersionOnly,
  provisionSchemaVersion,
  type AckReceipt,
  type AckReceiptVerifier,
  type MutationApplier,
  type OutboxTransport,
  type PgExecutor,
  type PgTransactor,
  type SchemaReadyToken,
} from '../src/ha-outbox-pg.js';

const CATALOG = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'ha-outbox-manifest-catalog.fixture.json'), 'utf8')) as {
  cols: Record<string, unknown>[]; cons: Record<string, unknown>[]; idx: Record<string, unknown>[]; rel: Record<string, unknown>[]; trig: Record<string, unknown>[]; pol: Record<string, unknown>[];
};
function catalogRows(sql: string): Record<string, unknown>[] | undefined {
  if (sql.includes('information_schema.columns')) return CATALOG.cols;
  if (sql.includes('pg_get_constraintdef')) return CATALOG.cons;
  if (sql.includes('pg_indexes')) return CATALOG.idx;
  if (sql.includes('pg_get_triggerdef')) return CATALOG.trig;
  if (sql.includes('pg_policy')) return CATALOG.pol;
  if (sql.includes('rel.relkind')) return CATALOG.rel;
  return undefined;
}

/**
 * Snapshot-based in-memory transactional store for LOGIC only. transaction()
 * runs on a CLONE and commits on success; a throw discards it (ROLLBACK/crash).
 * Reports SERIALIZABLE + rowCount so isolation and exactly-1 write assertions
 * run. It CANNOT prove lock/lease/ordering under concurrency — that is
 * ha-outbox-pg.realpg.test.ts (integrated producer->transport->receiver).
 */
interface Row { stream_id: string; source_epoch: string; sequence: number; fence_token: string; op_digest: string; mutation: unknown; acked_at: string | null; quarantined_at: string | null }
interface Applied { stream_id: string; source_epoch: string; sequence: number; op_digest: string }
interface Cp { source_epoch: string; sequence: number; last_digest: string }
interface Lease { token: string | null; until: number | null }
interface State { fence: Map<string, bigint>; src: Map<string, Cp>; rcv: Map<string, Cp>; rows: Row[]; applied: Applied[]; lease: Map<string, Lease>; quar: Applied[]; version: number }

let CLOCK = 1000;
class MemoryPg implements PgTransactor {
  isolation = 'serializable';
  state: State = { fence: new Map(), src: new Map(), rcv: new Map(), rows: [], applied: [], lease: new Map(), quar: [], version: HA_OUTBOX_SCHEMA_VERSION };
  crashBeforeCommit = false;
  queryHook: ((sql: string) => Promise<void>) | undefined;
  private clone(s: State): State {
    return { fence: new Map(s.fence), src: new Map([...s.src].map(([k, v]) => [k, { ...v }])), rcv: new Map([...s.rcv].map(([k, v]) => [k, { ...v }])), rows: s.rows.map((r) => ({ ...r })), applied: s.applied.map((a) => ({ ...a })), lease: new Map([...s.lease].map(([k, v]) => [k, { ...v }])), quar: s.quar.map((q) => ({ ...q })), version: s.version };
  }
  async transaction<T>(fn: (exec: PgExecutor) => Promise<T>, _opts?: { signal?: AbortSignal }): Promise<T> {
    const work = this.clone(this.state);
    const result = await fn(makeExec(work, this.isolation, this.queryHook));
    if (this.crashBeforeCommit) { this.crashBeforeCommit = false; throw new Error('crash before commit'); }
    this.state = work;
    return result;
  }
  provision(streamId: string, epoch: string): void { this.state.fence.set(streamId, 0n); this.state.src.set(streamId, { source_epoch: epoch, sequence: 0, last_digest: '' }); this.state.rcv.set(streamId, { source_epoch: epoch, sequence: 0, last_digest: '' }); }
  srcSeq(streamId: string): number { return this.state.src.get(streamId)!.sequence; }
  rcvSeq(streamId: string): number { return this.state.rcv.get(streamId)!.sequence; }
  rowCount(streamId: string): number { return this.state.rows.filter((r) => r.stream_id === streamId).length; }
  rowsOf(streamId: string): Row[] { return this.state.rows.filter((r) => r.stream_id === streamId).sort((a, b) => a.sequence - b.sequence); }
  setFence(streamId: string, t: bigint): void { this.state.fence.set(streamId, t); }
  deleteFence(streamId: string): void { this.state.fence.delete(streamId); }
  holdLease(streamId: string): void { this.state.lease.set(streamId, { token: 'someone-else', until: CLOCK + 1_000_000 }); }
}

function makeExec(s: State, isolation: string, queryHook?: (sql: string) => Promise<void>): PgExecutor {
  const now = () => CLOCK++;
  let pinned = 'public';
  return {
    async query(sql: string, params: unknown[] = []) {
      await queryHook?.(sql);
      const P = params as string[];
      const out = (rows: Record<string, unknown>[], rc?: number) => ({ rows, rowCount: rc ?? rows.length });
      if (sql.includes('SHOW transaction_isolation')) return out([{ transaction_isolation: isolation }]);
      if (sql.includes('set_config')) { pinned = P[1].split(',')[0]; return out([{ set_config: P[1] }]); }
      const catalog = catalogRows(sql); if (catalog) return out(catalog);
      if (sql.includes('current_schema()')) return out([{ s:pinned,p1:pinned,p2:'pg_catalog',p3:null,n:2 }]);
      if (sql.includes('FROM ha_outbox_meta')) return out([{ schema_version: s.version }]);
      if (sql.includes('FROM ha_outbox_fence') && sql.includes('SELECT fence_token')) { const t = s.fence.get(P[0]); return out(t === undefined ? [] : [{ fence_token: t.toString() }]); }
      if (sql.includes('INSERT INTO ha_outbox_fence')) { const cur = s.fence.get(P[0]) ?? 0n; const n = cur + 1n; s.fence.set(P[0], n); return out([{ fence_token: n.toString() }]); }
      if (sql.includes('count(*)')) return out([{ n: String(s.rows.filter((r) => r.stream_id === P[0] && r.acked_at === null && r.quarantined_at === null).length) }]);
      if (sql.includes('FROM ha_outbox_source_checkpoint')) { const c = s.src.get(P[0]); return out(c ? [{ source_epoch: c.source_epoch, sequence: c.sequence }] : []); }
      if (sql.includes('FROM ha_outbox_receiver_checkpoint')) { const c = s.rcv.get(P[0]); return out(c ? [{ source_epoch: c.source_epoch, sequence: c.sequence }] : []); }
      if (sql.includes('INSERT INTO ha_outbox_rows')) { s.rows.push({ stream_id: P[0], source_epoch: P[1], sequence: Number(P[2]), fence_token: P[3], op_digest: P[4], mutation: JSON.parse(P[5]), acked_at: null, quarantined_at: null }); return out([{}]); }
      if (sql.includes('UPDATE ha_outbox_source_checkpoint SET sequence')) { s.src.get(P[0])!.sequence = Number(P[1]); return out([{}]); }
      if (sql.includes('UPDATE ha_outbox_receiver_checkpoint SET sequence')) { const c = s.rcv.get(P[0])!; c.sequence = Number(P[1]); c.last_digest = P[2]; return out([{}]); }
      if (sql.includes('INSERT INTO ha_outbox_applied')) { s.applied.push({ stream_id: P[0], source_epoch: P[1], sequence: Number(P[2]), op_digest: P[3] }); return out([{}]); }
      if (sql.includes('FROM ha_outbox_applied')) { const a = s.applied.find((x) => x.stream_id === P[0] && x.source_epoch === P[1] && x.sequence === Number(P[2])); return out(a ? [{ op_digest: a.op_digest }] : []); }
      // publisher lease
      if (sql.includes('INSERT INTO ha_outbox_publisher_lease')) {
        const cur = s.lease.get(P[0]); const t = now();
        if (!cur || cur.token === null || cur.until === null || cur.until < t) { s.lease.set(P[0], { token: P[1], until: t + Number(P[2]) }); return out([{ lease_token: P[1] }], 1); }
        return out([], 0);
      }
      if (sql.includes('SELECT lease_token FROM ha_outbox_publisher_lease')) { const l = s.lease.get(P[0]); return out(l ? [{ lease_token: l.token }] : []); }
      if (sql.includes('UPDATE ha_outbox_publisher_lease SET lease_token = NULL')) { const l = s.lease.get(P[0]); if (l && l.token === P[1]) { l.token = null; l.until = null; return out([{}], 1); } return out([], 0); }
      // lowest deliverable
      if (sql.includes('FROM ha_outbox_rows') && sql.includes('ORDER BY sequence ASC LIMIT 1')) {
        const r = s.rows.filter((x) => x.stream_id === P[0] && x.acked_at === null && x.quarantined_at === null).sort((a, b) => a.sequence - b.sequence)[0];
        return out(r ? [{ source_epoch: r.source_epoch, sequence: r.sequence, fence_token: r.fence_token, op_digest: r.op_digest, mutation: r.mutation }] : []);
      }
      // ack
      if (sql.includes('UPDATE ha_outbox_rows SET published_at')) { const r = s.rows.find((x) => x.stream_id === P[0] && x.source_epoch === P[1] && x.sequence === Number(P[2]) && x.acked_at === null && x.quarantined_at === null && x.op_digest === P[3]); if (!r) return out([], 0); r.acked_at = 'now'; return out([{}], 1); }
      // quarantine
      if (sql.includes('INSERT INTO ha_outbox_quarantine')) { const k = s.quar.find((q) => q.stream_id === P[0] && q.source_epoch === P[1] && q.sequence === Number(P[2])); if (k) return out([], 0); s.quar.push({ stream_id: P[0], source_epoch: P[1], sequence: Number(P[2]), op_digest: P[3] }); return out([{}], 1); }
      if (sql.includes('UPDATE ha_outbox_rows SET quarantined_at')) { const r = s.rows.find((x) => x.stream_id === P[0] && x.source_epoch === P[1] && x.sequence === Number(P[2]) && x.acked_at === null && x.quarantined_at === null); if (!r) return out([], 0); r.quarantined_at = 'now'; return out([{}], 1); }
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
const applier: MutationApplier<Clean> = { async applyInTx(_e, r) { expect(Object.isFrozen(r)).toBe(true); expect(Object.isFrozen(r.mutation)).toBe(true); applied.push(`${r.sequence}:${(r.mutation as Clean).pairId}`); } };
const SID = 'bpc:pair:default/v1';
const readyFor = (d: PgTransactor) => provisionSchemaVersion(d, 'public');
const RECEIVER_ID = 'receiver-A', KEY_ID = 'k1';
// Signature binds keyId + record digest + DECISION, so a swapped decision fails verify.
const sign = (r: OutboxRecord<unknown>, decision: ReceiverDecision) => `${KEY_ID}:${r.opDigest}:${decision}`;
const receiptFor = (r: OutboxRecord<unknown>, decision: ReceiverDecision): AckReceipt => ({ streamId: r.streamId, sourceEpoch: r.sourceEpoch, sequence: r.sequence, opDigest: r.opDigest, decision, receiverId: RECEIVER_ID, keyId: KEY_ID, issuedAt: 'now', signature: sign(r, decision) });
const verifier: AckReceiptVerifier = {
  async verify(receipt, record) {
    expect(Object.isFrozen(receipt)).toBe(true); expect(Object.isFrozen(record)).toBe(true); expect(Object.isFrozen(record.mutation)).toBe(true);
    if (receipt.receiverId !== RECEIVER_ID || receipt.keyId !== KEY_ID) throw new ContractValidationError('unknown/unauthorized receiver');
    if (receipt.signature !== sign(record, receipt.decision)) throw new ContractValidationError('bad ACK signature (forged/unsigned or decision not covered)');
  },
};
const dig = (streamId: string, sourceEpoch: string, sequence: number, fenceToken: string, m: Clean) =>
  canonicalOpDigest<Clean>({ streamId, sourceEpoch, sequence, fenceToken, mutation: m as SanitizedMutation<Clean> });

describe('PgDurableOutbox / receiver / publisher / fence (#16, adversarial LOGIC)', () => {
  let db: MemoryPg; let outbox: PgDurableOutbox<Raw, Clean>; let ready: SchemaReadyToken;
  beforeEach(async () => { db = new MemoryPg(); db.provision(SID, 'e1'); applied.length = 0; ready = await readyFor(db);
    outbox = new PgDurableOutbox(db, ready, { streamId: SID, sanitizer, maxPendingRows: 100, backpressure: 'fail-authoritative-mutation' }); });

  it('schema version gate passes at current version, fails on drift', async () => {
    await assertSchemaVersionOnly(db, 'public');
    db.state.version = HA_OUTBOX_SCHEMA_VERSION + 1;
    await expect(assertSchemaVersionOnly(db, 'public')).rejects.toThrow(/schema version mismatch/);
  });

  it('append allocates seq>=1, binds fence, sanitizes; atomic', async () => {
    const h = await outbox.withOutboxTx((tx) => outbox.appendInTx(tx, { streamId: SID, rawMutation: { pairId: 'p1', secret: 'X' }, fenceToken: 0n }));
    expect(h.sequence).toBe(1); expect(h.fenceToken).toBe('0'); expect(db.rowCount(SID)).toBe(1);
    expect('secret' in (db.state.rows[0].mutation as object)).toBe(false);
  });

  it('runs the external source-fence check after mutation work and rolls back on denial', async () => {
    let checks = 0;
    const fenced = new PgDurableOutbox(db, ready, {
      streamId: SID, sanitizer, maxPendingRows: 100,
      backpressure: 'fail-authoritative-mutation',
      preCommitCheck: async () => { checks++; throw new ContractValidationError('source lease expired (fail closed)'); },
    });
    await expect(fenced.withOutboxTx(async (tx, exec) => {
      await fenced.appendInTx(tx, { streamId: SID, rawMutation: { pairId: 'blocked' }, fenceToken: 0n });
      await exec.query('UPDATE ha_outbox_source_checkpoint SET sequence = $2 WHERE stream_id = $1', [SID, 99]);
    })).rejects.toThrow(/lease expired/);
    expect(checks).toBe(1);
    expect(db.rowCount(SID)).toBe(0);
    expect(db.srcSeq(SID)).toBe(0);
  });

  it('does not invoke the source-fence check for a read-only scope', async () => {
    let checks = 0;
    const fenced = new PgDurableOutbox(db, ready, {
      streamId: SID, sanitizer, maxPendingRows: 100,
      backpressure: 'fail-authoritative-mutation', preCommitCheck: async () => { checks++; },
    });
    await fenced.withOutboxTx(async () => 'read');
    expect(checks).toBe(0);
  });
  it('snapshots raw append input before the first awaited query (TOCTOU)', async () => {
    const entered = deferred(); const release = deferred();
    db.queryHook = async (sql) => { if (sql.includes('SELECT fence_token')) { entered.resolve(); await release.promise; } };
    const raw = { pairId: 'ORIGINAL', secret: 'X' };
    const pending = outbox.withOutboxTx((tx) => outbox.appendInTx(tx, { streamId: SID, rawMutation: raw, fenceToken: 0n }));
    await entered.promise;
    raw.pairId = 'EVIL'; raw.secret = 'CHANGED';
    release.resolve(); await pending;
    expect(db.rowsOf(SID)[0].mutation).toEqual({ pairId: 'ORIGINAL' });
  });
  it('rejects proxy/accessor append inputs before any outbox query', async () => {
    const queries: string[] = [];
    db.queryHook = async (sql) => { queries.push(sql); };
    const proxied = new Proxy({ pairId: 'p1' }, {});
    await expect(outbox.withOutboxTx((tx) => outbox.appendInTx(tx, { streamId: SID, rawMutation: proxied, fenceToken: 0n }))).rejects.toThrow(/proxy/);
    const accessor = Object.defineProperty({}, 'pairId', { enumerable: true, get: () => 'p1' }) as Raw;
    await expect(outbox.withOutboxTx((tx) => outbox.appendInTx(tx, { streamId: SID, rawMutation: accessor, fenceToken: 0n }))).rejects.toThrow(/accessor/);
    // Transaction setup necessarily queries before the callback; neither malformed
    // input reaches the outbox fence/admission queries or commits a row.
    expect(queries.some((sql) => sql.includes('ha_outbox_fence'))).toBe(false); expect(db.rowCount(SID)).toBe(0);
  });
  it('rejects an invalid tx before sanitizer or input inspection', async () => {
    let sanitizerCalls = 0, proxyTraps = 0;
    const guardedSanitizer: MutationSanitizer<Raw, Clean> = {
      sanitize(raw) { sanitizerCalls++; return sanitizer.sanitize(raw); },
      assertSanitized: sanitizer.assertSanitized,
    };
    const guarded = new PgDurableOutbox(db, ready, { streamId: SID, sanitizer: guardedSanitizer, maxPendingRows: 100, backpressure: 'fail-authoritative-mutation' });
    const input = new Proxy({ streamId: SID, rawMutation: { pairId: 'p1' }, fenceToken: 0n }, { getPrototypeOf(target) { proxyTraps++; return Reflect.getPrototypeOf(target); } });
    await expect(guarded.appendInTx({} as never, input)).rejects.toThrow(/transaction|bound|expired/i);
    expect(sanitizerCalls).toBe(0); expect(proxyTraps).toBe(0); expect(db.rowCount(SID)).toBe(0);
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
    const ob = new PgDurableOutbox(db, ready, { streamId: SID, sanitizer, maxPendingRows: 3, backpressure: 'fail-authoritative-mutation' });
    for (let i = 0; i < 3; i++) await ob.withOutboxTx((tx) => ob.appendInTx(tx, { streamId: SID, rawMutation: { pairId: 'p' + i }, fenceToken: 0n }));
    await expect(ob.withOutboxTx((tx) => ob.appendInTx(tx, { streamId: SID, rawMutation: { pairId: 'p4' }, fenceToken: 0n }))).rejects.toBeInstanceOf(OutboxBackpressureError);
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
  const rcvFor = (sid: string) => new PgReceiverCheckpoint<Clean>(db, sid, sanitizer, applier, ready);
  const apply = (rcv: PgReceiverCheckpoint<Clean>, rec: OutboxRecord<Clean>) => rcv.verifyAndApplyDelivered(rec);
  const mk = (sid: string, seq: number, m: Clean, fence = '0'): OutboxRecord<Clean> => ({ contractVersion: '1', streamId: sid, sourceEpoch: 'e1', sequence: seq, fenceToken: fence, opDigest: dig(sid, 'e1', seq, fence, m), mutation: m as SanitizedMutation<Clean> });

  it('#1 tampered payload with preserved opDigest is reject-fork', async () => {
    db.provision('r1/v1', 'e1'); const rcv = rcvFor('r1/v1');
    const tampered: OutboxRecord<Clean> = { ...mk('r1/v1', 1, { pairId: 'p1' }), mutation: { pairId: 'HACKED' } as SanitizedMutation<Clean> };
    expect(await apply(rcv, tampered)).toBe('reject-fork');
    expect(applied.length).toBe(0);
  });
  it('snapshots the complete delivered record before transaction awaits (TOCTOU)', async () => {
    db.provision('r-snapshot/v1', 'e1'); const rcv = rcvFor('r-snapshot/v1');
    const entered = deferred(); const release = deferred();
    db.queryHook = async (sql) => { if (sql.includes('SHOW transaction_isolation')) { entered.resolve(); await release.promise; } };
    const record = mk('r-snapshot/v1', 1, { pairId: 'ORIGINAL' });
    const pending = apply(rcv, record);
    await entered.promise;
    (record.mutation as Clean).pairId = 'EVIL'; record.opDigest = 'f'.repeat(64);
    release.resolve();
    expect(await pending).toBe('applied');
    expect(applied).toEqual(['1:ORIGINAL']);
  });
  it('rejects an invalid receiver tx before inspecting a hostile record', async () => {
    db.provision('r-invalid-tx/v1', 'e1'); const rcv = rcvFor('r-invalid-tx/v1'); let traps = 0;
    const hostile = new Proxy(mk('r-invalid-tx/v1', 1, { pairId: 'p1' }), { getPrototypeOf(target) { traps++; return Reflect.getPrototypeOf(target); } });
    await expect(rcv.verifyAndApplyInTx({} as never, hostile)).rejects.toThrow(/transaction|bound|expired/i);
    expect(traps).toBe(0); expect(applied).toEqual([]);
  });
  it('#2 fence exact equality — FUTURE, STALE, MISSING all reject-fence', async () => {
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
    db.state.src.get('r7/v1')!.sequence = 99;
    expect(await apply(rcv, mk('r7/v1', 1, { pairId: 'p1' }))).toBe('applied');
    expect(db.rcvSeq('r7/v1')).toBe(1); expect(db.srcSeq('r7/v1')).toBe(99);
  });
  it('receiver gap / epoch', async () => {
    db.provision('r4/v1', 'e1'); const rcv = rcvFor('r4/v1');
    expect(await apply(rcv, mk('r4/v1', 1, { pairId: 'p1' }))).toBe('applied');
    expect(await apply(rcv, mk('r4/v1', 3, { pairId: 'p3' }))).toBe('reject-gap');
    const other: OutboxRecord<Clean> = { ...mk('r4/v1', 2, { pairId: 'p2' }), sourceEpoch: 'e9', opDigest: dig('r4/v1', 'e9', 2, '0', { pairId: 'p2' }) };
    expect(await apply(rcv, other)).toBe('reject-epoch');
  });

  // ── publisher: per-stream ordered lease + signed-decision ACK (H1/H2 logic) ──
  const pubFor = (t: OutboxTransport, v: AckReceiptVerifier = verifier) => new PgDurablePublisher<Clean>(db, SID, t, 'quarantine', sanitizer, v, ready, { leaseMs: 30_000 });
  const seed = async (n: number) => { for (let i = 0; i < n; i++) await outbox.withOutboxTx((tx) => outbox.appendInTx(tx, { streamId: SID, rawMutation: { pairId: 'p' + i }, fenceToken: 0n })); };

  it('(H1) delivers lowest-first and ACKs each on applied/duplicate-ok', async () => {
    await seed(3);
    const order: number[] = [];
    const pub = pubFor({ async deliverAndAwaitAck(r) { expect(Object.isFrozen(r)).toBe(true); expect(Object.isFrozen(r.mutation)).toBe(true); order.push(r.sequence); return receiptFor(r, r.sequence === 2 ? 'duplicate-ok' : 'applied'); } });
    expect(await pub.drainOnce()).toEqual({ published: 3, acked: 3, quarantined: 0, retriable: false });
    expect(order).toEqual([1, 2, 3]); // strict order
    expect(db.rowsOf(SID).every((r) => r.acked_at !== null)).toBe(true);
  });
  it('(H1) transient reject (reject-gap/reject-fence) does NOT ack — retriable, stops, no advance', async () => {
    await seed(3);
    for (const decision of ['reject-gap', 'reject-fence'] as ReceiverDecision[]) {
      const fresh = new MemoryPg(); fresh.provision(SID, 'e1');
      const freshReady = await readyFor(fresh);
      const ob = new PgDurableOutbox(fresh, freshReady, { streamId: SID, sanitizer, maxPendingRows: 100, backpressure: 'quarantine' });
      for (let i = 0; i < 3; i++) await ob.withOutboxTx((tx) => ob.appendInTx(tx, { streamId: SID, rawMutation: { pairId: 'p' + i }, fenceToken: 0n }));
      const pub = new PgDurablePublisher<Clean>(fresh, SID, { async deliverAndAwaitAck(r) { return receiptFor(r, decision); } }, 'quarantine', sanitizer, verifier, freshReady, { leaseMs: 30_000 });
      const res = await pub.drainOnce();
      expect(res.acked).toBe(0); expect(res.retriable).toBe(true); expect(res.published).toBe(1); // stopped after the first
      expect(fresh.rowsOf(SID).every((r) => r.acked_at === null && r.quarantined_at === null)).toBe(true);
    }
  });
  it('(H1) terminal reject (reject-fork) quarantines, never acks, halts drain', async () => {
    await seed(3);
    const pub = pubFor({ async deliverAndAwaitAck(r) { return receiptFor(r, r.sequence === 1 ? 'reject-fork' : 'applied'); } });
    const res = await pub.drainOnce();
    expect(res.quarantined).toBe(1); expect(res.acked).toBe(0); expect(res.published).toBe(1);
    const rows = db.rowsOf(SID);
    expect(rows[0].quarantined_at).not.toBeNull(); expect(rows[0].acked_at).toBeNull();
    expect(db.state.quar.length).toBe(1);
  });
  it('(HIGH2) a forged/unsigned receipt or a swapped decision is denied — not acked', async () => {
    await seed(1);
    const forgedSig = pubFor({ async deliverAndAwaitAck(r) { return { ...receiptFor(r, 'applied'), signature: 'FORGED' }; } });
    await expect(forgedSig.drainOnce()).rejects.toThrow(/signature|forged|decision/i);
    expect(db.rowsOf(SID)[0].acked_at).toBeNull();
    // swapped decision: claims 'applied' but signs 'reject-gap' -> verify fails (sig binds decision)
    const swapped = pubFor({ async deliverAndAwaitAck(r) { return { ...receiptFor(r, 'reject-gap'), decision: 'applied' as ReceiverDecision }; } });
    await expect(swapped.drainOnce()).rejects.toThrow(/signature|decision/i);
    expect(db.rowsOf(SID)[0].acked_at).toBeNull();
  });
  it('snapshots the full ACK before awaiting its verifier (TOCTOU)', async () => {
    await seed(1);
    const entered = deferred(); const release = deferred(); let returned!: AckReceipt;
    const gatedVerifier: AckReceiptVerifier = { async verify(receipt, record) { entered.resolve(); await release.promise; await verifier.verify(receipt, record); } };
    const pub = pubFor({ async deliverAndAwaitAck(r) { returned = receiptFor(r, 'reject-fork'); return returned; } }, gatedVerifier);
    const pending = pub.drainOnce();
    await entered.promise;
    returned.decision = 'applied'; returned.signature = 'EVIL';
    release.resolve();
    const result = await pending;
    expect(result).toMatchObject({ acked: 0, quarantined: 1 });
    expect(db.rowsOf(SID)[0].acked_at).toBeNull();
  });

  it('rejects accessor/inherited transport shapes before verification', async () => {
    await seed(1);
    const bad = Object.create({ decision: 'applied' }) as AckReceipt;
    Object.assign(bad, { streamId: SID, sourceEpoch: 'e1', sequence: 1, opDigest: db.rowsOf(SID)[0].op_digest, receiverId: RECEIVER_ID, keyId: KEY_ID, issuedAt: 'now', signature: 'x' });
    const pub = pubFor({ async deliverAndAwaitAck() { return bad; } }, { async verify() { throw new Error('must not reach verifier'); } });
    await expect(pub.drainOnce()).rejects.toThrow(/plain objects|unexpected or missing fields/);
    expect(db.rowsOf(SID)[0].acked_at).toBeNull();
  });
  it('rejects proxy ACK shapes before calling the verifier', async () => {
    await seed(1); let verified = false;
    const proxied = new Proxy(receiptFor(mk(SID, 1, { pairId: 'p0' }), 'applied'), {});
    const pub = pubFor({ async deliverAndAwaitAck() { return proxied; } }, { async verify() { verified = true; } });
    await expect(pub.drainOnce()).rejects.toThrow(/proxy/);
    expect(verified).toBe(false); expect(db.rowsOf(SID)[0].acked_at).toBeNull();
  });
  it('(R4) an unknown/forged receiver decision is fail-closed — not acked, not quarantined', async () => {
    await seed(1);
    const passAll: AckReceiptVerifier = { async verify() {} };
    const pub = pubFor({ async deliverAndAwaitAck(r) { return { ...receiptFor(r, 'applied'), decision: 'totally-bogus' as ReceiverDecision }; } }, passAll);
    await expect(pub.drainOnce()).rejects.toThrow(/unknown receiver decision/);
    const row = db.rowsOf(SID)[0];
    expect(row.acked_at).toBeNull(); expect(row.quarantined_at).toBeNull();
  });
  it('(#4) a mismatched-tuple receipt is denied even if it passes signature verify', async () => {
    await seed(1);
    const passAll: AckReceiptVerifier = { async verify() {} };
    const bad = pubFor({ async deliverAndAwaitAck(r) { return { ...receiptFor(r, 'applied'), opDigest: 'f'.repeat(64) }; } }, passAll);
    await expect(bad.drainOnce()).rejects.toThrow(/does not match/);
    expect(db.rowsOf(SID)[0].acked_at).toBeNull();
  });
  it('(#5) publisher fails closed on a corrupted stored row (digest mismatch)', async () => {
    await seed(1);
    db.rowsOf(SID)[0].mutation = { pairId: 'TAMPERED' };
    const pub = pubFor({ async deliverAndAwaitAck(r) { return receiptFor(r, 'applied'); } });
    await expect(pub.drainOnce()).rejects.toThrow(/corrupted outbox row/);
    expect(db.rowsOf(SID)[0].acked_at).toBeNull();
  });
  it('snapshots a database row once and rejects a changing proxy before transport', async () => {
    await seed(1); let reads = 0, transported = false;
    db.rowsOf(SID)[0].mutation = new Proxy({ pairId: 'p0' }, { get(target, key, receiver) { if (key === 'pairId') return reads++ === 0 ? 'p0' : 'EVIL'; return Reflect.get(target, key, receiver); } });
    const pub = pubFor({ async deliverAndAwaitAck(r) { transported = true; return receiptFor(r, 'applied'); } });
    await expect(pub.drainOnce()).rejects.toThrow(/proxy/);
    expect(transported).toBe(false); expect(db.rowsOf(SID)[0].acked_at).toBeNull();
  });
  it('(H2) single-active lease: a second publisher on the same stream gets nothing while the lease is held', async () => {
    await seed(2);
    db.holdLease(SID); // simulate publisher A holding an unexpired lease
    const pubB = pubFor({ async deliverAndAwaitAck(r) { return receiptFor(r, 'applied'); } });
    expect(await pubB.drainOnce()).toEqual({ published: 0, acked: 0, quarantined: 0, retriable: true });
    expect(db.rowsOf(SID).every((r) => r.acked_at === null)).toBe(true);
  });
  it('transport failure leaves the row undelivered (retry)', async () => {
    await seed(1);
    let fail = true;
    const pub = pubFor({ async deliverAndAwaitAck(r) { if (fail) throw new Error('transport down'); return receiptFor(r, 'applied'); } });
    await expect(pub.drainOnce()).rejects.toThrow('transport');
    expect(db.rowsOf(SID)[0].acked_at).toBeNull();
    fail = false; expect((await pub.drainOnce()).acked).toBe(1);
  });

  it('(#6/MED8) unsafe DB bigint sequence is a ContractValidationError', async () => {
    db.provision('r6/v1', 'e1'); db.state.rcv.get('r6/v1')!.sequence = Number.MAX_SAFE_INTEGER + 10;
    const rcv = rcvFor('r6/v1');
    await expect(apply(rcv, mk('r6/v1', 1, { pairId: 'p1' }))).rejects.toBeInstanceOf(ContractValidationError);
  });
  it('promotion fence is monotonic + persisted', async () => {
    const fence = new PgPromotionFence(db, ready);
    const t1 = await fence.acquire('f/v1'); const t2 = await fence.acquire('f/v1');
    expect(t2).toBeGreaterThan(t1); expect(await fence.current('f/v1')).toBe(t2);
  });
});

/**
 * (R11) STRUCTURED-SCOPE regression: the capability-scoped executor must reject
 * queries after its transaction scope ends AND force a rollback if a mutation was
 * launched but not awaited. A controllable transactor gates a chosen query so the
 * interleaving is deterministic (no timing luck).
 */
function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve!: () => void;
  const promise = new Promise<void>((r) => { resolve = r; });
  return { promise, resolve };
}
class GatedPg implements PgTransactor {
  executed: string[] = [];
  committed: boolean | null = null;
  discarded = false;
  insertRan = false;
  gateOn: string | null = null;
  rejectOn: string | null = null;
  gate = deferred();
  async transaction<T>(fn: (exec: PgExecutor) => Promise<T>, opts?: { signal?: AbortSignal }): Promise<T> {
    const signal = opts?.signal;
    const exec: PgExecutor = {
      query: async (sql: string) => {
        this.executed.push(sql);
        if (this.rejectOn && sql.includes(this.rejectOn)) throw new Error('injected query failure');
        if (this.gateOn && sql.includes(this.gateOn)) {
          // honor the abort signal: on deadline the transactor cancels the query
          await new Promise<void>((resolve, reject) => {
            if (signal?.aborted) return reject(signal.reason as Error);
            signal?.addEventListener('abort', () => reject(signal.reason as Error), { once: true });
            this.gate.promise.then(resolve);
          });
        }
        const out = (rows: Record<string, unknown>[], rc?: number) => ({ rows, rowCount: rc ?? rows.length });
        if (sql.includes('SHOW transaction_isolation')) return out([{ transaction_isolation: 'serializable' }]);
        if (sql.includes('set_config')) return out([{ set_config: 'public' }]);
        const catalog = catalogRows(sql); if (catalog) return out(catalog);
        if (sql.includes('current_schema()')) return out([{ s:'public',p1:'public',p2:'pg_catalog',p3:null,n:2 }]);
        if (sql.includes('FROM ha_outbox_meta')) return out([{ schema_version: HA_OUTBOX_SCHEMA_VERSION }]);
        if (sql.includes('FROM ha_outbox_fence')) return out([{ fence_token: '0' }]);
        if (sql.includes('count(*)')) return out([{ n: '0' }]);
        if (sql.includes('FROM ha_outbox_source_checkpoint')) return out([{ source_epoch: 'e1', sequence: 0 }]);
        if (sql.includes('INSERT INTO ha_outbox_rows')) { this.insertRan = true; return out([{}], 1); }
        if (sql.includes('UPDATE ha_outbox_source_checkpoint')) return out([{}], 1);
        return out([]);
      },
    };
    try { const r = await fn(exec); this.committed = true; return r; }
    catch (e) { this.committed = false; this.discarded = true; throw e; } // (R12) discard the connection on error
  }
}
const gatedOutbox = async (db: GatedPg) => new PgDurableOutbox<Raw, Clean>(db, await readyFor(db), { streamId: SID, sanitizer, maxPendingRows: 100, backpressure: 'quarantine' });
const tick = () => new Promise<void>((r) => setTimeout(r, 10));

describe('(R11) capability-scoped executor / structured scope', () => {
  it('(a) a blocked read then a LATER query is denied; the tx rolls back; no mutation runs', async () => {
    const db = new GatedPg(); db.gateOn = 'FROM ha_outbox_fence';
    const outbox = await gatedOutbox(db);
    let captured: unknown;
    const p = outbox.withOutboxTx(async (tx) => { void outbox.appendInTx(tx, { streamId: SID, rawMutation: { pairId: 'x' }, fenceToken: 0n }).catch((e) => { captured = e; }); return 'x'; });
    await tick();            // appendInTx is parked on the gated fence read; the callback has returned
    db.gate.resolve();       // release the read
    await expect(p).rejects.toThrow(/in-flight|scope/);
    expect(String(captured)).toMatch(/outside its active/);
    expect(db.insertRan).toBe(false);   // the INSERT never ran (denied after scope closed)
    expect(db.committed).toBe(false);   // and the tx rolled back
  });

  it('(b) a FIRST mutation launched unawaited runs but CANNOT commit — the tx rolls back', async () => {
    const db = new GatedPg(); db.gateOn = 'INSERT INTO ha_outbox_rows';
    const outbox = await gatedOutbox(db);
    const p = outbox.withOutboxTx(async (_tx, scoped) => { void scoped.query('INSERT INTO ha_outbox_rows (stream_id) VALUES ($1)', ['x']); return 'x'; });
    await tick();            // the INSERT is in-flight (gated); the callback has returned
    db.gate.resolve();       // let the INSERT actually execute on the connection
    await expect(p).rejects.toThrow(/in-flight|scope/);
    expect(db.insertRan).toBe(true);    // the mutation DID execute…
    expect(db.committed).toBe(false);   // …but the scope forced a ROLLBACK — never committed
  });

  it('(c) the callback only ever gets the scoped proxy; it is dead after the scope (raw exec never exposed)', async () => {
    const db = new GatedPg();
    const outbox = await gatedOutbox(db);
    let scopedRef: PgExecutor | undefined;
    await outbox.withOutboxTx(async (_tx, scoped) => { scopedRef = scoped; return 'ok'; });
    expect(() => scopedRef!.query('SELECT 1')).toThrow(/outside its active/);
  });

  it('(d) the normal fully-awaited path commits', async () => {
    const db = new GatedPg();
    const outbox = await gatedOutbox(db);
    const h = await outbox.withOutboxTx((tx) => outbox.appendInTx(tx, { streamId: SID, rawMutation: { pairId: 'x' }, fenceToken: 0n }));
    expect(h.sequence).toBe(1);
    expect(db.insertRan).toBe(true);
    expect(db.committed).toBe(true);
  });

  it('(e) a NEVER-RESOLVING query is bounded by the scope deadline; the tx rolls back and the connection is discarded', async () => {
    const db = new GatedPg(); db.gateOn = 'FROM ha_outbox_fence'; // gate is never resolved
    const outbox = new PgDurableOutbox<Raw, Clean>(db, await readyFor(db), { streamId: SID, sanitizer, maxPendingRows: 100, backpressure: 'quarantine', scopeDeadlineMs: 50 });
    const p = outbox.withOutboxTx((tx) => outbox.appendInTx(tx, { streamId: SID, rawMutation: { pairId: 'x' }, fenceToken: 0n }));
    await expect(p).rejects.toThrow(/deadline/);
    expect(db.committed).toBe(false);   // never committed
    expect(db.discarded).toBe(true);    // connection discarded, not reused
  });

  it('(f) a FAST unawaited REJECTION is retained and fails the scope (not lost); the tx rolls back', async () => {
    const db = new GatedPg(); db.rejectOn = 'INSERT INTO ha_outbox_rows';
    const outbox = await gatedOutbox(db);
    const p = outbox.withOutboxTx(async (_tx, scoped) => { void scoped.query('INSERT INTO ha_outbox_rows (stream_id) VALUES ($1)', ['x']).catch(() => {}); return 'x'; });
    await expect(p).rejects.toThrow(/rejected — rolling back|in-flight|scope/);
    expect(db.committed).toBe(false);   // the fast rejection was observed -> rollback, not a false commit
  });

  it('(g/R13) the deadline covers enterCriticalTx: a hung isolation/pin query is bounded', async () => {
    const db = new GatedPg(); const ready = await readyFor(db); db.gateOn = 'SHOW transaction_isolation'; // the FIRST critical query, before any bound-tx work
    const outbox = new PgDurableOutbox<Raw, Clean>(db, ready, { streamId: SID, sanitizer, maxPendingRows: 100, backpressure: 'quarantine', scopeDeadlineMs: 50 });
    const p = outbox.withOutboxTx((tx) => outbox.appendInTx(tx, { streamId: SID, rawMutation: { pairId: 'x' }, fenceToken: 0n }));
    await expect(p).rejects.toThrow(/deadline/);
    expect(db.committed).toBe(false);
    expect(db.discarded).toBe(true);
  });

  it('(h/R13/MED) scopeDeadlineMs is centrally validated (finite integer, 1..2^31-1) for outbox AND receiver', async () => {
    const db = new GatedPg(); const ready = await readyFor(db);
    for (const bad of [0, -1, 1.5, 2_147_483_648, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => new PgDurableOutbox<Raw, Clean>(db, ready, { streamId: SID, sanitizer, maxPendingRows: 1, backpressure: 'quarantine', scopeDeadlineMs: bad })).toThrow(/scopeDeadlineMs/);
      expect(() => new PgReceiverCheckpoint<Clean>(db, SID, sanitizer, applier, ready, undefined, bad)).toThrow(/scopeDeadlineMs/);
    }
  });
});
