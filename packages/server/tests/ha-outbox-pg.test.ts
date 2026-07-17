import { describe, expect, it, beforeEach } from 'vitest';

import {
  ContractValidationError,
  OutboxBackpressureError,
  StaleFenceError,
  type MutationSanitizer,
  type OutboxRecord,
  type SanitizedMutation,
} from '../src/ha-outbox-contract.js';
import {
  PgDurableOutbox,
  PgDurablePublisher,
  PgPromotionFence,
  PgReceiverCheckpoint,
  type MutationApplier,
  type OutboxTransport,
  type PgExecutor,
  type PgTransactor,
} from '../src/ha-outbox-pg.js';

/**
 * Snapshot-based in-memory transactional store that models the EXACT queries the
 * impl issues. transaction() runs against a CLONE and commits it only on success;
 * a throw discards the clone — i.e. real ROLLBACK / crash semantics. This proves
 * the single-authority LOGIC and crash-atomicity. The real two-node PostgreSQL
 * + Redis failover/split-brain drill is separate (#16 stays OPEN).
 */
interface Row { stream_id: string; source_epoch: string; sequence: number; fence_token: string; op_digest: string; mutation: unknown; published_at: string | null; acked_at: string | null }
interface State { fence: Map<string, bigint>; checkpoint: Map<string, { source_epoch: string; sequence: number; last_digest: string }>; rows: Row[] }

class MemoryPg implements PgTransactor {
  state: State = { fence: new Map(), checkpoint: new Map(), rows: [] };
  /** set to true to simulate a crash right before COMMIT of the next tx. */
  crashBeforeCommit = false;

  private clone(s: State): State {
    return { fence: new Map(s.fence), checkpoint: new Map([...s.checkpoint].map(([k, v]) => [k, { ...v }])), rows: s.rows.map((r) => ({ ...r })) };
  }

  async transaction<T>(fn: (exec: PgExecutor) => Promise<T>): Promise<T> {
    const work = this.clone(this.state);
    const exec = makeExec(work);
    const result = await fn(exec);
    if (this.crashBeforeCommit) { this.crashBeforeCommit = false; throw new Error('crash before commit'); }
    this.state = work; // COMMIT
    return result;
  }

  // test helpers (bypass tx)
  provision(streamId: string, epoch: string): void {
    this.state.fence.set(streamId, 0n);
    this.state.checkpoint.set(streamId, { source_epoch: epoch, sequence: 0, last_digest: '' });
  }
  provisionReceiver = this.provision;
  seq(streamId: string): number { return this.state.checkpoint.get(streamId)!.sequence; }
  rowCount(streamId: string): number { return this.state.rows.filter((r) => r.stream_id === streamId).length; }
  setFence(streamId: string, t: bigint): void { this.state.fence.set(streamId, t); }
}

function makeExec(s: State): PgExecutor {
  return {
    async query(sql: string, params: unknown[] = []) {
      const P = params as string[];
      if (sql.includes('FROM ha_outbox_fence') && sql.includes('SELECT fence_token')) {
        const t = s.fence.get(P[0]); return { rows: t === undefined ? [] : [{ fence_token: t.toString() }] };
      }
      if (sql.includes('INSERT INTO ha_outbox_fence')) {
        const cur = s.fence.get(P[0]) ?? 0n; const next = cur + 1n; s.fence.set(P[0], next); return { rows: [{ fence_token: next.toString() }] };
      }
      if (sql.includes("count(*)")) {
        const n = s.rows.filter((r) => r.stream_id === P[0] && r.acked_at === null).length; return { rows: [{ n }] };
      }
      if (sql.includes('SELECT source_epoch, sequence, last_digest')) {
        const c = s.checkpoint.get(P[0]); return { rows: c ? [{ source_epoch: c.source_epoch, sequence: c.sequence, last_digest: c.last_digest }] : [] };
      }
      if (sql.includes('SELECT source_epoch, sequence FROM ha_outbox_checkpoint')) {
        const c = s.checkpoint.get(P[0]); return { rows: c ? [{ source_epoch: c.source_epoch, sequence: c.sequence }] : [] };
      }
      if (sql.includes('INSERT INTO ha_outbox_rows')) {
        s.rows.push({ stream_id: P[0], source_epoch: P[1], sequence: Number(P[2]), fence_token: P[3], op_digest: P[4], mutation: JSON.parse(P[5]), published_at: null, acked_at: null }); return { rows: [] };
      }
      if (sql.includes('UPDATE ha_outbox_checkpoint SET sequence = $2 WHERE')) {
        const c = s.checkpoint.get(P[0])!; c.sequence = Number(P[1]); return { rows: [] };
      }
      if (sql.includes('UPDATE ha_outbox_checkpoint SET sequence=$2, last_digest=$3')) {
        const c = s.checkpoint.get(P[0])!; c.sequence = Number(P[1]); c.last_digest = P[2]; return { rows: [] };
      }
      if (sql.includes('FROM ha_outbox_rows') && sql.includes('acked_at IS NULL ORDER BY sequence')) {
        const rows = s.rows.filter((r) => r.stream_id === P[0] && r.acked_at === null).sort((a, b) => a.sequence - b.sequence)
          .map((r) => ({ source_epoch: r.source_epoch, sequence: r.sequence, fence_token: r.fence_token, op_digest: r.op_digest, mutation: r.mutation }));
        return { rows };
      }
      if (sql.includes('UPDATE ha_outbox_rows SET published_at')) {
        const r = s.rows.find((x) => x.stream_id === P[0] && x.source_epoch === P[1] && x.sequence === Number(P[2]))!; r.published_at = 'now'; r.acked_at = 'now'; return { rows: [] };
      }
      if (sql.includes('SELECT op_digest FROM ha_outbox_rows')) {
        const r = s.rows.find((x) => x.stream_id === P[0] && x.source_epoch === P[1] && x.sequence === Number(P[2])); return { rows: r ? [{ op_digest: r.op_digest }] : [] };
      }
      throw new Error('unhandled SQL in fake: ' + sql.slice(0, 60));
    },
  };
}

// ── sanitizer + applier fixtures ──
interface Raw { pairId: string; secret?: string }
interface Clean { pairId: string }
const sanitizer: MutationSanitizer<Raw, Clean> = {
  sanitize(raw) { if (typeof raw.pairId !== 'string') throw new ContractValidationError('bad'); return { pairId: raw.pairId } as SanitizedMutation<Clean>; },
  assertSanitized(c): asserts c is SanitizedMutation<Clean> { if (!c || typeof c !== 'object' || 'secret' in (c as object)) throw new ContractValidationError('unsanitized'); },
};
const applied: string[] = [];
const applier: MutationApplier<Clean> = { async applyInTx(_e, record) { applied.push(`${record.sequence}:${(record.mutation as Clean).pairId}`); } };
const SID = 'bpc:pair:default/v1';

describe('PgDurableOutbox / receiver / fence (#16 impl, adversarial)', () => {
  let db: MemoryPg; let outbox: PgDurableOutbox<Raw, Clean>;
  beforeEach(() => { db = new MemoryPg(); db.provision(SID, 'e1'); applied.length = 0;
    outbox = new PgDurableOutbox(db, { streamId: SID, sanitizer, maxPendingRows: 3, backpressure: 'fail-authoritative-mutation' }); });

  it('append allocates seq>=1, binds fence, sanitizes; commit is atomic', async () => {
    const h = await outbox.withOutboxTx((tx) => outbox.appendInTx(tx, { streamId: SID, rawMutation: { pairId: 'p1', secret: 'X' }, fenceToken: 0n }));
    expect(h.sequence).toBe(1);
    expect(h.fenceToken).toBe('0');
    expect(db.rowCount(SID)).toBe(1);
    expect('secret' in (db.state.rows[0].mutation as object)).toBe(false); // sanitized
  });

  it('CRASH before commit rolls back the mutation + sequence (no partial state)', async () => {
    db.crashBeforeCommit = true;
    await expect(outbox.withOutboxTx((tx) => outbox.appendInTx(tx, { streamId: SID, rawMutation: { pairId: 'p1' }, fenceToken: 0n }))).rejects.toThrow('crash');
    expect(db.rowCount(SID)).toBe(0); // no row
    expect(db.seq(SID)).toBe(0);      // sequence not advanced
  });

  it('stale fence token fails closed', async () => {
    db.setFence(SID, 5n);
    await expect(outbox.withOutboxTx((tx) => outbox.appendInTx(tx, { streamId: SID, rawMutation: { pairId: 'p1' }, fenceToken: 4n }))).rejects.toBeInstanceOf(StaleFenceError);
  });

  it('backpressure fails closed at the bound (never sheds)', async () => {
    for (let i = 0; i < 3; i++) await outbox.withOutboxTx((tx) => outbox.appendInTx(tx, { streamId: SID, rawMutation: { pairId: 'p' + i }, fenceToken: 0n }));
    await expect(outbox.withOutboxTx((tx) => outbox.appendInTx(tx, { streamId: SID, rawMutation: { pairId: 'p4' }, fenceToken: 0n }))).rejects.toBeInstanceOf(OutboxBackpressureError);
    expect(db.rowCount(SID)).toBe(3); // nothing shed
  });

  it('publisher drains in order + records ACK; transport failure leaves row unacked (retry)', async () => {
    for (let i = 1; i <= 2; i++) await outbox.withOutboxTx((tx) => outbox.appendInTx(tx, { streamId: SID, rawMutation: { pairId: 'p' + i }, fenceToken: 0n }));
    const delivered: number[] = [];
    let fail = true;
    const transport: OutboxTransport = { async deliver(r) { if (fail && r.sequence === 2) throw new Error('transport down'); delivered.push(r.sequence); } };
    const pub = new PgDurablePublisher(db, SID, transport, 'quarantine');
    await expect(pub.drainOnce()).rejects.toThrow('transport'); // seq2 fails → whole tx rolls back
    expect(db.state.rows.every((r) => r.acked_at === null)).toBe(true); // nothing acked (atomic)
    fail = false;
    const res = await pub.drainOnce();
    expect(res.acked).toBe(2);
    expect(delivered).toContain(1); expect(delivered).toContain(2);
  });

  it('receiver: apply / idempotent-duplicate / gap / fork / stale / fence', async () => {
    db.provision('recv/v1', 'e1');
    const rcv = new PgReceiverCheckpoint('recv/v1', sanitizer, applier);
    const mk = (seq: number, digest: string, fence = '0'): OutboxRecord<Clean> => ({ contractVersion: '1', streamId: 'recv/v1', sourceEpoch: 'e1', sequence: seq, fenceToken: fence, opDigest: digest, mutation: { pairId: 'p' + seq } as SanitizedMutation<Clean> });
    const D = 'a'.repeat(64), D2 = 'b'.repeat(64);
    expect(await db.transaction((e) => bindAndApply(rcv, e, mk(1, D)))).toBe('applied');
    expect(await db.transaction((e) => bindAndApply(rcv, e, mk(1, D)))).toBe('duplicate-ok');   // same key+digest
    expect(await db.transaction((e) => bindAndApply(rcv, e, mk(1, D2)))).toBe('reject-stale');   // <= cp, no matching row
    expect(await db.transaction((e) => bindAndApply(rcv, e, mk(3, D)))).toBe('reject-gap');       // > cp+1
    db.setFence('recv/v1', 9n);
    expect(await db.transaction((e) => bindAndApply(rcv, e, mk(2, D, '4')))).toBe('reject-fence'); // stale token
    expect(applied).toEqual(['1:p1']); // only the one real apply
  });

  it('receiver CRASH between apply and checkpoint leaves checkpoint unchanged', async () => {
    db.provision('recv2/v1', 'e1');
    const rcv = new PgReceiverCheckpoint('recv2/v1', sanitizer, applier);
    const rec: OutboxRecord<Clean> = { contractVersion: '1', streamId: 'recv2/v1', sourceEpoch: 'e1', sequence: 1, fenceToken: '0', opDigest: 'a'.repeat(64), mutation: { pairId: 'p1' } as SanitizedMutation<Clean> };
    db.crashBeforeCommit = true;
    await expect(db.transaction((e) => bindAndApply(rcv, e, rec))).rejects.toThrow('crash');
    expect(db.state.checkpoint.get('recv2/v1')!.sequence).toBe(0); // checkpoint not advanced
  });

  it('promotion fence is monotonic + persisted', async () => {
    const fence = new PgPromotionFence(db);
    const t1 = await fence.acquire('f/v1');
    const t2 = await fence.acquire('f/v1');
    expect(t2).toBeGreaterThan(t1);
    expect(await fence.current('f/v1')).toBe(t2);
  });
});

// helper: bind an executor to a DurableTx and call verifyAndApplyInTx.
async function bindAndApply(rcv: PgReceiverCheckpoint<Clean>, exec: PgExecutor, record: OutboxRecord<Clean>) {
  // Reuse the outbox's tx-binding by wrapping: the receiver expects a DurableTx.
  const { createBoundTx } = await import('../src/ha-outbox-pg.js');
  return rcv.verifyAndApplyInTx(createBoundTx(exec), record);
}
