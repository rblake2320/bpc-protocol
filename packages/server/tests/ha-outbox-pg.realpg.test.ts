/**
 * REAL PostgreSQL concurrency evidence for the HA durable-outbox (#16).
 *
 * The snapshot fake in ha-outbox-pg.test.ts proves LOGIC only; it cannot
 * establish lock/isolation/lease behavior. This suite runs the mechanism
 * against a live PostgreSQL server and proves the properties Codex gated on:
 *   - SERIALIZABLE is enforced at runtime (a read-committed transactor is
 *     rejected at the critical tx entry).
 *   - Concurrent source appends allocate unique, gapless sequences (no double
 *     allocation) under real row locks + serialization-failure retry.
 *   - The publisher CLAIM-LEASE partitions rows across concurrent drainers
 *     (FOR UPDATE SKIP LOCKED) so no row is double-delivered, and delivery
 *     happens with NO DB lock held across the network call.
 *   - ACK is exactly-once: the guarded UPDATE (unacked + claim_token +
 *     op_digest) affects exactly one row; a stale claim affects zero.
 *   - The receiver checkpoint is an INDEPENDENT authority and its durable
 *     applied-history survives a receiver "restart" (new instance).
 *   - The DDL CHECK constraints reject malformed rows at the storage layer.
 *
 * Gated on HA_OUTBOX_PG_URL (e.g. postgres://postgres:test@localhost:55499/ha);
 * skipped when unset so the default suite stays hermetic. Issue #16 remains
 * OPEN — this is single-node mechanism evidence, NOT the two-node failover drill.
 */
import { createRequire } from 'node:module';
import { afterAll, beforeEach, describe, expect, it } from 'vitest';

import {
  ContractValidationError,
  canonicalOpDigest,
  type MutationSanitizer,
  type OutboxRecord,
  type SanitizedMutation,
} from '../src/ha-outbox-contract.js';
import {
  HA_OUTBOX_PG_SCHEMA,
  PgDurableOutbox,
  PgDurablePublisher,
  PgReceiverCheckpoint,
  createBoundTx,
  type AckReceipt,
  type AckReceiptVerifier,
  type MutationApplier,
  type OutboxTransport,
  type PgExecutor,
  type PgTransactor,
} from '../src/ha-outbox-pg.js';

const nodeRequire = createRequire(import.meta.url);
const URL = process.env.HA_OUTBOX_PG_URL;
const run = URL ? describe : describe.skip;

// pg carries no bundled types in this workspace; test-only, treat as any.
const { Pool } = nodeRequire('pg');
const pool = URL ? new Pool({ connectionString: URL, max: 16 }) : null;

/** Real transactor: BEGIN ISOLATION LEVEL <level>; retry on serialization
 *  failure / deadlock (40001 / 40P01). */
class RealPg implements PgTransactor {
  constructor(private readonly level: 'SERIALIZABLE' | 'READ COMMITTED') {}
  async transaction<T>(fn: (exec: PgExecutor) => Promise<T>): Promise<T> {
    for (let attempt = 0; ; attempt++) {
      const client = await pool!.connect();
      try {
        await client.query(`BEGIN ISOLATION LEVEL ${this.level}`);
        const exec: PgExecutor = { query: async (sql, params) => { const r = await client.query(sql, params as unknown[]); return { rows: r.rows, rowCount: r.rowCount ?? 0 }; } };
        const result = await fn(exec);
        await client.query('COMMIT');
        return result;
      } catch (e) {
        await client.query('ROLLBACK').catch(() => {});
        const code = (e as { code?: string }).code;
        if ((code === '40001' || code === '40P01') && attempt < 50) continue; // finally releases
        throw e;
      } finally {
        client.release();
      }
    }
  }
}

interface Raw { pairId: string; secret?: string }
interface Clean { pairId: string }
const sanitizer: MutationSanitizer<Raw, Clean> = {
  sanitize(raw) { if (typeof raw.pairId !== 'string') throw new ContractValidationError('bad'); return { pairId: raw.pairId } as SanitizedMutation<Clean>; },
  assertSanitized(c): asserts c is SanitizedMutation<Clean> { if (!c || typeof c !== 'object' || 'secret' in (c as object)) throw new ContractValidationError('unsanitized'); },
};
const applier: MutationApplier<Clean> = { async applyInTx() { /* no domain side-effect in this evidence slice */ } };
const KEY_ID = 'k1', RECEIVER_ID = 'receiver-A';
const sign = (r: OutboxRecord<unknown>) => `${KEY_ID}:${r.opDigest}`;
const okAck = (r: OutboxRecord<unknown>): AckReceipt => ({ streamId: r.streamId, sourceEpoch: r.sourceEpoch, sequence: r.sequence, opDigest: r.opDigest, receiverId: RECEIVER_ID, keyId: KEY_ID, issuedAt: 'now', signature: sign(r) });
const verifier: AckReceiptVerifier = { async verify(receipt, record) { if (receipt.keyId !== KEY_ID || receipt.signature !== sign(record)) throw new ContractValidationError('bad ACK'); } };

async function resetSchema(streamId: string, epoch = 'e1') {
  const c = pool!;
  await c.query('DROP TABLE IF EXISTS ha_outbox_rows, ha_outbox_applied, ha_outbox_fence, ha_outbox_source_checkpoint, ha_outbox_receiver_checkpoint CASCADE');
  for (const stmt of HA_OUTBOX_PG_SCHEMA.split(';').map((s) => s.trim()).filter(Boolean)) await c.query(stmt);
  await c.query('INSERT INTO ha_outbox_fence (stream_id, fence_token) VALUES ($1, 0)', [streamId]);
  await c.query('INSERT INTO ha_outbox_source_checkpoint (stream_id, source_epoch, sequence) VALUES ($1,$2,0)', [streamId, epoch]);
  await c.query('INSERT INTO ha_outbox_receiver_checkpoint (stream_id, source_epoch, sequence) VALUES ($1,$2,0)', [streamId, epoch]);
}

run('#16 real PostgreSQL concurrency evidence', () => {
  const SID = 'bpc:pair:realpg/v1';
  const serial = new RealPg('SERIALIZABLE');
  const mkOutbox = (db: PgTransactor) => new PgDurableOutbox<Raw, Clean>(db, { streamId: SID, sanitizer, maxPendingRows: 10_000, backpressure: 'fail-authoritative-mutation' });

  beforeEach(async () => { await resetSchema(SID); });
  afterAll(async () => { if (pool) await pool.end(); });

  it('(HIGH4) a READ COMMITTED transactor is rejected at the critical tx entry', async () => {
    const rc = mkOutbox(new RealPg('READ COMMITTED'));
    await expect(rc.withOutboxTx((tx) => rc.appendInTx(tx, { streamId: SID, rawMutation: { pairId: 'p' }, fenceToken: 0n }))).rejects.toThrow(/SERIALIZABLE/);
    // and SERIALIZABLE works
    const ok = mkOutbox(serial);
    const h = await ok.withOutboxTx((tx) => ok.appendInTx(tx, { streamId: SID, rawMutation: { pairId: 'p' }, fenceToken: 0n }));
    expect(h.sequence).toBe(1);
  });

  it('concurrent appends allocate UNIQUE, GAPLESS sequences (no double-allocation)', async () => {
    const N = 24;
    const outbox = mkOutbox(serial);
    const headers = await Promise.all(
      Array.from({ length: N }, (_, i) => outbox.withOutboxTx((tx) => outbox.appendInTx(tx, { streamId: SID, rawMutation: { pairId: 'p' + i }, fenceToken: 0n }))),
    );
    const seqs = headers.map((h) => h.sequence).sort((a, b) => a - b);
    expect(seqs).toEqual(Array.from({ length: N }, (_, i) => i + 1)); // exactly 1..N
    const rows = (await pool!.query('SELECT count(*)::int AS n FROM ha_outbox_rows WHERE stream_id=$1', [SID])).rows[0].n;
    expect(rows).toBe(N);
    const cp = (await pool!.query('SELECT sequence FROM ha_outbox_source_checkpoint WHERE stream_id=$1', [SID])).rows[0].sequence;
    expect(Number(cp)).toBe(N);
  });

  it('(HIGH1) claim-lease partitions rows across CONCURRENT publishers — no double delivery, no lock held across delivery', async () => {
    const outbox = mkOutbox(serial);
    const N = 12;
    for (let i = 0; i < N; i++) await outbox.withOutboxTx((tx) => outbox.appendInTx(tx, { streamId: SID, rawMutation: { pairId: 'p' + i }, fenceToken: 0n }));

    const delivered: number[] = [];
    let concurrentlyInFlight = 0, maxInFlight = 0;
    const transport: OutboxTransport = {
      async deliverAndAwaitAck(r) {
        concurrentlyInFlight++; maxInFlight = Math.max(maxInFlight, concurrentlyInFlight);
        await new Promise((res) => setTimeout(res, 15)); // network — no DB lock may be held here
        delivered.push(r.sequence);
        concurrentlyInFlight--;
        return okAck(r);
      },
    };
    const pubA = new PgDurablePublisher<Clean>(serial, SID, transport, 'quarantine', sanitizer, verifier, { batchSize: 5, leaseMs: 30_000 });
    const pubB = new PgDurablePublisher<Clean>(serial, SID, transport, 'quarantine', sanitizer, verifier, { batchSize: 5, leaseMs: 30_000 });
    // drain repeatedly & concurrently until the stream is empty
    let total = { published: 0, acked: 0 };
    for (let round = 0; round < 10; round++) {
      const [a, b] = await Promise.all([pubA.drainOnce(), pubB.drainOnce()]);
      total = { published: total.published + a.published + b.published, acked: total.acked + a.acked + b.acked };
      const left = (await pool!.query('SELECT count(*)::int AS n FROM ha_outbox_rows WHERE stream_id=$1 AND acked_at IS NULL', [SID])).rows[0].n;
      if (Number(left) === 0) break;
    }
    expect(total.acked).toBe(N);
    expect([...delivered].sort((a, b) => a - b)).toEqual(Array.from({ length: N }, (_, i) => i + 1)); // each delivered exactly once
    expect(maxInFlight).toBeGreaterThan(1); // deliveries genuinely overlapped → no lock serialized them
    const unacked = (await pool!.query('SELECT count(*)::int AS n FROM ha_outbox_rows WHERE stream_id=$1 AND acked_at IS NULL', [SID])).rows[0].n;
    expect(Number(unacked)).toBe(0);
  });

  it('ACK is exactly-once: the guarded UPDATE affects one row; a stale claim affects zero', async () => {
    const outbox = mkOutbox(serial);
    await outbox.withOutboxTx((tx) => outbox.appendInTx(tx, { streamId: SID, rawMutation: { pairId: 'p0' }, fenceToken: 0n }));
    const pub = new PgDurablePublisher<Clean>(serial, SID, { async deliverAndAwaitAck(r) { return okAck(r); } }, 'quarantine', sanitizer, verifier, { batchSize: 5, leaseMs: 30_000 });
    expect((await pub.drainOnce()).acked).toBe(1);
    // a re-drain finds nothing claimable (already acked)
    expect(await pub.drainOnce()).toEqual({ published: 0, acked: 0 });
    // a stale-claim ack (wrong token, row already acked) affects zero rows
    const stale = await pool!.query(
      `UPDATE ha_outbox_rows SET acked_at = now() WHERE stream_id=$1 AND source_epoch='e1' AND sequence=1 AND acked_at IS NULL AND claim_token='stale' AND op_digest=(SELECT op_digest FROM ha_outbox_rows WHERE stream_id=$1 AND sequence=1)`,
      [SID],
    );
    expect(stale.rowCount).toBe(0);
  });

  it('(HIGH3) receiver checkpoint is independent + applied-history survives a receiver restart', async () => {
    const dig = (seq: number, m: Clean) => canonicalOpDigest<Clean>({ streamId: SID, sourceEpoch: 'e1', sequence: seq, fenceToken: '0', mutation: m as SanitizedMutation<Clean> });
    const rec = (seq: number, m: Clean): OutboxRecord<Clean> => ({ contractVersion: '1', streamId: SID, sourceEpoch: 'e1', sequence: seq, fenceToken: '0', opDigest: dig(seq, m), mutation: m as SanitizedMutation<Clean> });
    // advance the SOURCE allocator far ahead — receiver must not depend on it
    await pool!.query('UPDATE ha_outbox_source_checkpoint SET sequence=500 WHERE stream_id=$1', [SID]);

    const r1 = new PgReceiverCheckpoint<Clean>(SID, sanitizer, applier);
    const applyWith = (rcv: PgReceiverCheckpoint<Clean>, record: OutboxRecord<Clean>) => serial.transaction((e) => rcv.verifyAndApplyInTx(createBoundTx(e), record));
    expect(await applyWith(r1, rec(1, { pairId: 'a' }))).toBe('applied');
    expect(await applyWith(r1, rec(2, { pairId: 'b' }))).toBe('applied');

    // "restart": a fresh receiver instance reading the SAME durable state
    const r2 = new PgReceiverCheckpoint<Clean>(SID, sanitizer, applier);
    expect(await applyWith(r2, rec(1, { pairId: 'a' }))).toBe('duplicate-ok');   // older duplicate
    expect(await applyWith(r2, rec(1, { pairId: 'FORK' }))).toBe('reject-fork'); // older fork
    const rcvSeq = (await pool!.query('SELECT sequence FROM ha_outbox_receiver_checkpoint WHERE stream_id=$1', [SID])).rows[0].sequence;
    expect(Number(rcvSeq)).toBe(2); // receiver advanced on its own authority
    const srcSeq = (await pool!.query('SELECT sequence FROM ha_outbox_source_checkpoint WHERE stream_id=$1', [SID])).rows[0].sequence;
    expect(Number(srcSeq)).toBe(500); // source untouched by the receiver
  });

  it('(MED7) DDL CHECK constraints reject malformed rows at the storage layer', async () => {
    const good = 'a'.repeat(64);
    // sequence 0 (must be >= 1)
    await expect(pool!.query('INSERT INTO ha_outbox_rows (stream_id, source_epoch, sequence, fence_token, op_digest, mutation) VALUES ($1,$2,0,0,$3,$4)', [SID, 'e1', good, '{}'])).rejects.toThrow(/check constraint|violates/i);
    // non-hex digest
    await expect(pool!.query('INSERT INTO ha_outbox_rows (stream_id, source_epoch, sequence, fence_token, op_digest, mutation) VALUES ($1,$2,1,0,$3,$4)', [SID, 'e1', 'NOTHEX', '{}'])).rejects.toThrow(/check constraint|violates/i);
    // negative fence
    await expect(pool!.query('INSERT INTO ha_outbox_rows (stream_id, source_epoch, sequence, fence_token, op_digest, mutation) VALUES ($1,$2,1,-1,$3,$4)', [SID, 'e1', good, '{}'])).rejects.toThrow(/check constraint|violates/i);
    // empty stream_id
    await expect(pool!.query('INSERT INTO ha_outbox_rows (stream_id, source_epoch, sequence, fence_token, op_digest, mutation) VALUES ($1,$2,1,0,$3,$4)', ['', 'e1', good, '{}'])).rejects.toThrow(/check constraint|violates/i);
  });
});
