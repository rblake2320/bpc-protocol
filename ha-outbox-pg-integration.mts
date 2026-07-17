/**
 * INTEGRATED real-PostgreSQL evidence for the HA durable-outbox (#16).
 *
 * Repo convention (like postgres-store-integration.mts): a tsx script that
 * REQUIRES BPC_TEST_POSTGRES_URL and THROWS if it is unset — so CI genuinely
 * executes it (no silent vitest skip). This is the authoritative proof of the
 * properties the snapshot fake cannot establish:
 *   - SERIALIZABLE enforced at runtime (READ COMMITTED transactor rejected).
 *   - Concurrent source appends allocate unique, gapless 1..N.
 *   - PER-STREAM ORDERED delivery (H2): a full producer->transport->RECEIVER
 *     pipeline with TWO concurrent publishers on one stream applies strictly
 *     1..N in order, the receiver NEVER returns reject-gap, nothing is lost or
 *     double-applied. Delivery order is asserted WITHOUT sorting.
 *   - Lease hand-off preserves order: a publisher that stops mid-stream hands
 *     off to another that continues in order with no gap/loss.
 *   - Signed-decision ACK (H1): the source ACKs ONLY on applied|duplicate-ok; a
 *     terminal reject quarantines (never acked, never dropped); a transient
 *     reject leaves the row for retry; ACK is exactly-once.
 *   - Independent receiver checkpoint + applied-history survives restart.
 *   - fence CHECK is integral and below the contract's 10^39 bound; DDL CHECKs
 *     reject malformed rows; schema-version gate fails closed on drift.
 *
 * Single-node mechanism evidence — NOT the two-node failover drill (#16 OPEN).
 */
import assert from 'node:assert/strict';
import pg from 'pg';
import {
  HA_OUTBOX_PG_SCHEMA,
  HA_OUTBOX_SCHEMA_MANIFEST,
  HA_OUTBOX_SCHEMA_VERSION,
  PgDurableOutbox,
  PgDurablePublisher,
  PgReceiverCheckpoint,
  assertSchemaReady,
  assertSchemaVersion,
  attestSchema,
  canonicalOpDigest,
  ContractValidationError,
  createBoundTx,
  migrateSchemaToCurrent,
  provisionSchemaVersion,
  schemaManifest,
} from './packages/server/src/index.ts';
import type {
  AckReceipt,
  AckReceiptVerifier,
  MutationApplier,
  MutationSanitizer,
  OutboxRecord,
  OutboxTransport,
  PgExecutor,
  PgTransactor,
  ReceiverDecision,
  SanitizedMutation,
} from './packages/server/src/index.ts';

const connectionString = process.env['BPC_TEST_POSTGRES_URL'] ?? process.env['HA_OUTBOX_PG_URL'];
if (!connectionString) {
  throw new Error('BPC_TEST_POSTGRES_URL is required for the live PostgreSQL HA-outbox test');
}
const { Pool } = pg;
const pool = new Pool({ connectionString, max: 16 });

class RealPg implements PgTransactor {
  constructor(private readonly level: 'SERIALIZABLE' | 'READ COMMITTED') {}
  async transaction<T>(fn: (exec: PgExecutor) => Promise<T>): Promise<T> {
    for (let attempt = 0; ; attempt++) {
      const client = await pool.connect();
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
const serial = new RealPg('SERIALIZABLE');

interface Raw { pairId: string; secret?: string }
interface Clean { pairId: string }
const sanitizer: MutationSanitizer<Raw, Clean> = {
  sanitize(raw) { if (typeof raw.pairId !== 'string') throw new ContractValidationError('bad'); return { pairId: raw.pairId } as SanitizedMutation<Clean>; },
  assertSanitized(c): asserts c is SanitizedMutation<Clean> { if (!c || typeof c !== 'object' || 'secret' in (c as object)) throw new ContractValidationError('unsanitized'); },
};
const KEY_ID = 'k1', RECEIVER_ID = 'receiver-A';
const sign = (r: OutboxRecord<unknown>, decision: ReceiverDecision) => `${KEY_ID}:${r.opDigest}:${decision}`;
const receiptFor = (r: OutboxRecord<unknown>, decision: ReceiverDecision): AckReceipt => ({ streamId: r.streamId, sourceEpoch: r.sourceEpoch, sequence: r.sequence, opDigest: r.opDigest, decision, receiverId: RECEIVER_ID, keyId: KEY_ID, issuedAt: 'now', signature: sign(r, decision) });
const verifier: AckReceiptVerifier = {
  async verify(receipt, record) {
    if (receipt.keyId !== KEY_ID || receipt.receiverId !== RECEIVER_ID) throw new ContractValidationError('unauthorized receiver');
    if (receipt.signature !== sign(record, receipt.decision)) throw new ContractValidationError('bad ACK signature (decision not covered)');
  },
};
const mkOutbox = (db: PgTransactor, streamId: string) => new PgDurableOutbox<Raw, Clean>(db, { streamId, sanitizer, maxPendingRows: 100_000, backpressure: 'fail-authoritative-mutation' });

async function applyDDL(): Promise<void> {
  for (const stmt of HA_OUTBOX_PG_SCHEMA.split(';').map((s) => s.trim()).filter(Boolean)) await pool.query(stmt);
}
async function resetSchema(): Promise<void> {
  await pool.query('DROP SCHEMA IF EXISTS shadow CASCADE');
  await pool.query('DROP TABLE IF EXISTS ha_outbox_rows, ha_outbox_applied, ha_outbox_fence, ha_outbox_source_checkpoint, ha_outbox_receiver_checkpoint, ha_outbox_publisher_lease, ha_outbox_quarantine, ha_outbox_meta CASCADE');
  await applyDDL();
  await provisionSchemaVersion(serial); // attests the fresh schema, then stamps v2
}
async function provision(streamId: string, epoch = 'e1'): Promise<void> {
  await pool.query('INSERT INTO ha_outbox_fence (stream_id, fence_token) VALUES ($1,0)', [streamId]);
  await pool.query('INSERT INTO ha_outbox_source_checkpoint (stream_id, source_epoch, sequence) VALUES ($1,$2,0)', [streamId, epoch]);
  await pool.query('INSERT INTO ha_outbox_receiver_checkpoint (stream_id, source_epoch, sequence) VALUES ($1,$2,0)', [streamId, epoch]);
}
const unacked = async (sid: string) => Number((await pool.query('SELECT count(*)::int AS n FROM ha_outbox_rows WHERE stream_id=$1 AND acked_at IS NULL AND quarantined_at IS NULL', [sid])).rows[0].n);

/** A receiver-backed transport: delivering runs the REAL receiver in its own
 *  serializable tx and returns a signed receipt carrying the receiver decision.
 *  Every decision is recorded (with the sequence, in real delivery order). */
function receiverTransport(streamId: string, decisions: Array<{ seq: number; decision: ReceiverDecision }>): OutboxTransport {
  const receiver = new PgReceiverCheckpoint<Clean>(streamId, sanitizer, applierRecording);
  return {
    async deliverAndAwaitAck(record) {
      const decision = await serial.transaction((e) => receiver.verifyAndApplyInTx(createBoundTx(e), record as OutboxRecord<Clean>));
      decisions.push({ seq: record.sequence, decision });
      return receiptFor(record, decision);
    },
  };
}
const appliedOrder: number[] = [];
const applierRecording: MutationApplier<Clean> = { async applyInTx(_e, r) { appliedOrder.push(r.sequence); } };

let passed = 0;
async function check(name: string, fn: () => Promise<void>): Promise<void> {
  await resetSchema();
  appliedOrder.length = 0;
  await fn();
  passed++;
  console.log(`  ok - ${name}`);
}

async function main(): Promise<void> {
  console.log('# HA outbox integrated real-PG evidence');

  await check('schema version gate passes at current, fails on drift', async () => {
    await assertSchemaVersion(serial);
    await pool.query('UPDATE ha_outbox_meta SET schema_version = $1 WHERE id = 1', [HA_OUTBOX_SCHEMA_VERSION + 1]);
    await assert.rejects(() => assertSchemaVersion(serial), /schema version mismatch/);
  });

  await check('READ COMMITTED transactor is rejected; SERIALIZABLE works', async () => {
    const sid = 'sc:iso/v1'; await provision(sid);
    const rc = mkOutbox(new RealPg('READ COMMITTED'), sid);
    await assert.rejects(() => rc.withOutboxTx((tx) => rc.appendInTx(tx, { streamId: sid, rawMutation: { pairId: 'p' }, fenceToken: 0n })), /SERIALIZABLE/);
    const ok = mkOutbox(serial, sid);
    const h = await ok.withOutboxTx((tx) => ok.appendInTx(tx, { streamId: sid, rawMutation: { pairId: 'p' }, fenceToken: 0n }));
    assert.equal(h.sequence, 1);
  });

  await check('concurrent appends allocate unique, gapless 1..N', async () => {
    const sid = 'sc:alloc/v1'; await provision(sid); const N = 24;
    const ob = mkOutbox(serial, sid);
    const headers = await Promise.all(Array.from({ length: N }, (_, i) => ob.withOutboxTx((tx) => ob.appendInTx(tx, { streamId: sid, rawMutation: { pairId: 'p' + i }, fenceToken: 0n }))));
    assert.deepEqual(headers.map((h) => h.sequence).sort((a, b) => a - b), Array.from({ length: N }, (_, i) => i + 1));
    assert.equal(Number((await pool.query('SELECT sequence FROM ha_outbox_source_checkpoint WHERE stream_id=$1', [sid])).rows[0].sequence), N);
  });

  await check('(H1/H2) two concurrent publishers -> in-order, no reject-gap, no loss, no double', async () => {
    const sid = 'sc:ordered/v1'; await provision(sid); const N = 20;
    const ob = mkOutbox(serial, sid);
    for (let i = 0; i < N; i++) await ob.withOutboxTx((tx) => ob.appendInTx(tx, { streamId: sid, rawMutation: { pairId: 'p' + i }, fenceToken: 0n }));
    const decisions: Array<{ seq: number; decision: ReceiverDecision }> = [];
    const transport = receiverTransport(sid, decisions);
    const pubA = new PgDurablePublisher<Clean>(serial, sid, transport, 'quarantine', sanitizer, verifier, { leaseMs: 30_000 });
    const pubB = new PgDurablePublisher<Clean>(serial, sid, transport, 'quarantine', sanitizer, verifier, { leaseMs: 30_000 });
    for (let round = 0; round < 40; round++) {
      await Promise.all([pubA.drainOnce(), pubB.drainOnce()]);
      if ((await unacked(sid)) === 0) break;
    }
    // receiver NEVER saw a gap; applied strictly 1..N in real delivery order (unsorted)
    assert.ok(!decisions.some((d) => d.decision === 'reject-gap'), 'receiver returned reject-gap');
    assert.deepEqual(appliedOrder, Array.from({ length: N }, (_, i) => i + 1), 'receiver applied out of order or lost');
    assert.equal(await unacked(sid), 0, 'rows lost/unacked');
    assert.equal(Number((await pool.query('SELECT sequence FROM ha_outbox_receiver_checkpoint WHERE stream_id=$1', [sid])).rows[0].sequence), N);
    assert.equal(Number((await pool.query('SELECT count(*)::int AS n FROM ha_outbox_quarantine WHERE stream_id=$1', [sid])).rows[0].n), 0);
  });

  await check('lease hand-off preserves order: partial publisher then another finishes in order', async () => {
    const sid = 'sc:handoff/v1'; await provision(sid); const N = 10;
    const ob = mkOutbox(serial, sid);
    for (let i = 0; i < N; i++) await ob.withOutboxTx((tx) => ob.appendInTx(tx, { streamId: sid, rawMutation: { pairId: 'p' + i }, fenceToken: 0n }));
    const decisions: Array<{ seq: number; decision: ReceiverDecision }> = [];
    const receiver = new PgReceiverCheckpoint<Clean>(sid, sanitizer, applierRecording);
    let deliveredByA = 0;
    // Publisher A: short lease, stops (throws) after delivering 4
    const transportA: OutboxTransport = { async deliverAndAwaitAck(record) {
      if (deliveredByA >= 4) throw new Error('publisher A stopped');
      deliveredByA++;
      const d = await serial.transaction((e) => receiver.verifyAndApplyInTx(createBoundTx(e), record as OutboxRecord<Clean>));
      decisions.push({ seq: record.sequence, decision: d });
      return receiptFor(record, d);
    } };
    const pubA = new PgDurablePublisher<Clean>(serial, sid, transportA, 'quarantine', sanitizer, verifier, { leaseMs: 200 });
    await assert.rejects(() => pubA.drainOnce(), /publisher A stopped/);
    // wait for A's lease to expire, then B finishes the rest
    await new Promise((r) => setTimeout(r, 300));
    const transportB = receiverTransport(sid, decisions);
    // rebind B's receiver to the shared applied-order recorder (already global)
    const pubB = new PgDurablePublisher<Clean>(serial, sid, transportB, 'quarantine', sanitizer, verifier, { leaseMs: 30_000 });
    for (let round = 0; round < 20; round++) { await pubB.drainOnce(); if ((await unacked(sid)) === 0) break; }
    assert.ok(!decisions.some((d) => d.decision === 'reject-gap'), 'gap during hand-off');
    assert.deepEqual(appliedOrder, Array.from({ length: N }, (_, i) => i + 1), 'hand-off applied out of order');
    assert.equal(await unacked(sid), 0);
  });

  await check('(H1) terminal reject quarantines, never acks, halts', async () => {
    const sid = 'sc:quar/v1'; await provision(sid);
    const ob = mkOutbox(serial, sid);
    for (let i = 0; i < 3; i++) await ob.withOutboxTx((tx) => ob.appendInTx(tx, { streamId: sid, rawMutation: { pairId: 'p' + i }, fenceToken: 0n }));
    // transport forces a terminal reject-fork on seq 1
    const transport: OutboxTransport = { async deliverAndAwaitAck(record) { return receiptFor(record, record.sequence === 1 ? 'reject-fork' : 'applied'); } };
    const pub = new PgDurablePublisher<Clean>(serial, sid, transport, 'quarantine', sanitizer, verifier, { leaseMs: 30_000 });
    const res = await pub.drainOnce();
    assert.equal(res.quarantined, 1); assert.equal(res.acked, 0); assert.equal(res.published, 1);
    assert.equal(Number((await pool.query('SELECT count(*)::int AS n FROM ha_outbox_quarantine WHERE stream_id=$1', [sid])).rows[0].n), 1);
    assert.equal(Number((await pool.query("SELECT count(*)::int AS n FROM ha_outbox_rows WHERE stream_id=$1 AND acked_at IS NOT NULL", [sid])).rows[0].n), 0);
    assert.equal(Number((await pool.query('SELECT count(*)::int AS n FROM ha_outbox_rows WHERE stream_id=$1 AND quarantined_at IS NOT NULL', [sid])).rows[0].n), 1);
  });

  await check('(H1) transient reject leaves row unacked (retriable); ACK is exactly-once', async () => {
    const sid = 'sc:transient/v1'; await provision(sid);
    const ob = mkOutbox(serial, sid);
    await ob.withOutboxTx((tx) => ob.appendInTx(tx, { streamId: sid, rawMutation: { pairId: 'p0' }, fenceToken: 0n }));
    const transientPub = new PgDurablePublisher<Clean>(serial, sid, { async deliverAndAwaitAck(r) { return receiptFor(r, 'reject-fence'); } }, 'quarantine', sanitizer, verifier, { leaseMs: 30_000 });
    const t = await transientPub.drainOnce();
    assert.equal(t.acked, 0); assert.equal(t.retriable, true);
    assert.equal(await unacked(sid), 1, 'transient reject must not consume the row');
    // now deliver applied and confirm exactly-once
    const okPub = new PgDurablePublisher<Clean>(serial, sid, { async deliverAndAwaitAck(r) { return receiptFor(r, 'applied'); } }, 'quarantine', sanitizer, verifier, { leaseMs: 30_000 });
    assert.equal((await okPub.drainOnce()).acked, 1);
    assert.equal(await unacked(sid), 0);
    // stale guarded ack affects zero rows
    const stale = await pool.query("UPDATE ha_outbox_rows SET acked_at = now() WHERE stream_id=$1 AND sequence=1 AND acked_at IS NULL AND quarantined_at IS NULL AND op_digest='deadbeef'", [sid]);
    assert.equal(stale.rowCount, 0);
  });

  await check('receiver checkpoint independent + applied-history survives restart', async () => {
    const sid = 'sc:rcv/v1'; await provision(sid);
    await pool.query('UPDATE ha_outbox_source_checkpoint SET sequence=500 WHERE stream_id=$1', [sid]);
    const dig = (seq: number, m: Clean) => canonicalOpDigest<Clean>({ streamId: sid, sourceEpoch: 'e1', sequence: seq, fenceToken: '0', mutation: m as SanitizedMutation<Clean> });
    const rec = (seq: number, m: Clean): OutboxRecord<Clean> => ({ contractVersion: '1', streamId: sid, sourceEpoch: 'e1', sequence: seq, fenceToken: '0', opDigest: dig(seq, m), mutation: m as SanitizedMutation<Clean> });
    const applyWith = (rcv: PgReceiverCheckpoint<Clean>, r: OutboxRecord<Clean>) => serial.transaction((e) => rcv.verifyAndApplyInTx(createBoundTx(e), r));
    const r1 = new PgReceiverCheckpoint<Clean>(sid, sanitizer, applierRecording);
    assert.equal(await applyWith(r1, rec(1, { pairId: 'a' })), 'applied');
    assert.equal(await applyWith(r1, rec(2, { pairId: 'b' })), 'applied');
    const r2 = new PgReceiverCheckpoint<Clean>(sid, sanitizer, applierRecording); // restart
    assert.equal(await applyWith(r2, rec(1, { pairId: 'a' })), 'duplicate-ok');
    assert.equal(await applyWith(r2, rec(1, { pairId: 'FORK' })), 'reject-fork');
    assert.equal(Number((await pool.query('SELECT sequence FROM ha_outbox_receiver_checkpoint WHERE stream_id=$1', [sid])).rows[0].sequence), 2);
    assert.equal(Number((await pool.query('SELECT sequence FROM ha_outbox_source_checkpoint WHERE stream_id=$1', [sid])).rows[0].sequence), 500);
  });

  await check('(MED) fence CHECK is integral and below 10^39; DDL CHECKs reject malformed', async () => {
    const sid = 'sc:ddl/v1'; const good = 'a'.repeat(64);
    await assert.rejects(() => pool.query('INSERT INTO ha_outbox_fence (stream_id, fence_token) VALUES ($1, 1.5)', [sid]), /check constraint|violates/i);
    await assert.rejects(() => pool.query('INSERT INTO ha_outbox_fence (stream_id, fence_token) VALUES ($1, 1e40)', [sid]), /check constraint|violates/i);
    await pool.query('INSERT INTO ha_outbox_fence (stream_id, fence_token) VALUES ($1, 42)', [sid]); // integral in-range ok
    await assert.rejects(() => pool.query('INSERT INTO ha_outbox_rows (stream_id, source_epoch, sequence, fence_token, op_digest, mutation) VALUES ($1,$2,0,0,$3,$4)', [sid, 'e1', good, '{}']), /check constraint|violates/i);
    await assert.rejects(() => pool.query('INSERT INTO ha_outbox_rows (stream_id, source_epoch, sequence, fence_token, op_digest, mutation) VALUES ($1,$2,1,0,$3,$4)', [sid, 'e1', 'NOTHEX', '{}']), /check constraint|violates/i);
    await assert.rejects(() => pool.query('INSERT INTO ha_outbox_rows (stream_id, source_epoch, sequence, fence_token, op_digest, mutation) VALUES ($1,$2,1,1.5,$3,$4)', [sid, 'e1', good, '{}']), /check constraint|violates/i);
  });

  await check('(R5) live schema manifest matches the pinned manifest', async () => {
    const live = await serial.transaction((e) => schemaManifest(e));
    assert.equal(live, HA_OUTBOX_SCHEMA_MANIFEST, 'pinned HA_OUTBOX_SCHEMA_MANIFEST is stale — recompute for this PG major');
  });

  await check('(R5/HIGH1) attestation rejects weakened CHECK, missing index, and other malformed tables', async () => {
    // fresh schema attests fine
    await serial.transaction((e) => attestSchema(e));
    // (a) quarantined_at present but the op_digest CHECK removed -> attestation catches it
    await pool.query(`DO $$ DECLARE r record; BEGIN
      FOR r IN SELECT conname FROM pg_constraint c JOIN pg_class rel ON rel.oid=c.conrelid
               WHERE rel.relname='ha_outbox_rows' AND c.contype='c' AND pg_get_constraintdef(c.oid) LIKE '%op_digest%'
      LOOP EXECUTE 'ALTER TABLE ha_outbox_rows DROP CONSTRAINT '||quote_ident(r.conname); END LOOP; END $$;`);
    await assert.rejects(() => serial.transaction((e) => attestSchema(e)), /attestation failed/);
    await assert.rejects(() => migrateSchemaToCurrent(serial), /attestation failed/, 'migration must not stamp a weakened schema');

    // (b) missing/wrong partial deliverable index
    await resetSchema();
    await pool.query('DROP INDEX ha_outbox_rows_deliverable');
    await assert.rejects(() => serial.transaction((e) => attestSchema(e)), /attestation failed/);

    // (c) a malformed OTHER table (altered default on the source checkpoint)
    await resetSchema();
    await pool.query('ALTER TABLE ha_outbox_source_checkpoint ALTER COLUMN sequence DROP DEFAULT');
    await assert.rejects(() => serial.transaction((e) => attestSchema(e)), /attestation failed/);
  });

  await check('(R5/HIGH1) attestation is scoped to current_schema (same-name objects elsewhere cannot spoof or pollute)', async () => {
    // a same-named table in another schema does NOT rescue a broken current schema…
    await pool.query('CREATE SCHEMA shadow');
    await pool.query('CREATE TABLE shadow.ha_outbox_rows (stream_id text, source_epoch text, sequence bigint, fence_token numeric, op_digest text CHECK (op_digest ~ \'^[0-9a-f]{64}$\'), mutation jsonb)');
    await pool.query(`DO $$ DECLARE r record; BEGIN
      FOR r IN SELECT conname FROM pg_constraint c JOIN pg_class rel ON rel.oid=c.conrelid JOIN pg_namespace n ON n.oid=rel.relnamespace
               WHERE n.nspname='public' AND rel.relname='ha_outbox_rows' AND c.contype='c' AND pg_get_constraintdef(c.oid) LIKE '%op_digest%'
      LOOP EXECUTE 'ALTER TABLE public.ha_outbox_rows DROP CONSTRAINT '||quote_ident(r.conname); END LOOP; END $$;`);
    await assert.rejects(() => serial.transaction((e) => attestSchema(e)), /attestation failed/, 'broken current schema must fail even with a good same-name table elsewhere');
    // …and a malformed same-named table elsewhere does NOT break a good current schema
    await resetSchema();
    await pool.query('CREATE SCHEMA shadow');
    await pool.query('CREATE TABLE shadow.ha_outbox_rows (bogus int)');
    await serial.transaction((e) => attestSchema(e)); // still attests OK
  });

  await check('(R5) DDL never auto-bumps meta; only attested migration advances', async () => {
    await pool.query('UPDATE ha_outbox_meta SET schema_version = 1 WHERE id = 1');
    await applyDDL();
    assert.equal(Number((await pool.query('SELECT schema_version FROM ha_outbox_meta WHERE id=1')).rows[0].schema_version), 1, 'DDL must NOT auto-bump an existing meta row');
    await assert.rejects(() => assertSchemaVersion(serial), /schema version mismatch/);
    await migrateSchemaToCurrent(serial); // attests OK -> advances
    assert.equal(Number((await pool.query('SELECT schema_version FROM ha_outbox_meta WHERE id=1')).rows[0].schema_version), HA_OUTBOX_SCHEMA_VERSION);
    await assertSchemaVersion(serial);
  });

  await check('(R6/HIGH1) migration is forward-only: a FUTURE version is never downgraded, data preserved', async () => {
    const sid = 'sc:nodown/v1'; await provision(sid);
    const ob = mkOutbox(serial, sid);
    await ob.withOutboxTx((tx) => ob.appendInTx(tx, { streamId: sid, rawMutation: { pairId: 'keepme' }, fenceToken: 0n }));
    // simulate a future version sharing this exact catalog (semantic-only revision / pre-staged marker)
    await pool.query('UPDATE ha_outbox_meta SET schema_version = 3 WHERE id = 1');
    await assert.rejects(() => migrateSchemaToCurrent(serial), /refusing to downgrade/);
    assert.equal(Number((await pool.query('SELECT schema_version FROM ha_outbox_meta WHERE id=1')).rows[0].schema_version), 3, 'future version must be preserved');
    assert.equal(Number((await pool.query('SELECT count(*)::int AS n FROM ha_outbox_rows WHERE stream_id=$1', [sid])).rows[0].n), 1, 'data must be preserved on refused downgrade');
    // being already-current is a clean no-op
    await pool.query('UPDATE ha_outbox_meta SET schema_version = $1 WHERE id = 1', [HA_OUTBOX_SCHEMA_VERSION]);
    await migrateSchemaToCurrent(serial);
    assert.equal(Number((await pool.query('SELECT schema_version FROM ha_outbox_meta WHERE id=1')).rows[0].schema_version), HA_OUTBOX_SCHEMA_VERSION);
  });

  await check('(R6/HIGH2) assertSchemaReady catches post-stamp structural drift (version-only check does not)', async () => {
    await assertSchemaReady(serial); // fresh + stamped -> ready
    // validly stamped v2, then drop a CHECK while leaving meta = 2
    await pool.query(`DO $$ DECLARE r record; BEGIN
      FOR r IN SELECT conname FROM pg_constraint c JOIN pg_class rel ON rel.oid=c.conrelid
               WHERE rel.relname='ha_outbox_rows' AND c.contype='c' AND pg_get_constraintdef(c.oid) LIKE '%op_digest%'
      LOOP EXECUTE 'ALTER TABLE ha_outbox_rows DROP CONSTRAINT '||quote_ident(r.conname); END LOOP; END $$;`);
    assert.equal(Number((await pool.query('SELECT schema_version FROM ha_outbox_meta WHERE id=1')).rows[0].schema_version), HA_OUTBOX_SCHEMA_VERSION);
    await assertSchemaVersion(serial); // version-only check still passes (the bypass)
    await assert.rejects(() => assertSchemaReady(serial), /attestation failed/, 'readiness gate must catch structural drift');
    // dropping a table too
    await resetSchema();
    await assertSchemaReady(serial);
    await pool.query('DROP INDEX ha_outbox_rows_deliverable');
    await assert.rejects(() => assertSchemaReady(serial), /attestation failed/);
  });

  await check('(R5/HIGH2) quarantine conflict with a mismatched preexisting row fails closed', async () => {
    const sid = 'sc:qconf/v1'; await provision(sid);
    const ob = mkOutbox(serial, sid);
    await ob.withOutboxTx((tx) => ob.appendInTx(tx, { streamId: sid, rawMutation: { pairId: 'p0' }, fenceToken: 0n }));
    // plant a LYING quarantine row for (sid,e1,1): different digest + different decision
    await pool.query("INSERT INTO ha_outbox_quarantine (stream_id, source_epoch, sequence, op_digest, decision) VALUES ($1,'e1',1,$2,'reject-stale')", [sid, 'b'.repeat(64)]);
    const forkPub = new PgDurablePublisher<Clean>(serial, sid, { async deliverAndAwaitAck(r) { return receiptFor(r, 'reject-fork'); } }, 'quarantine', sanitizer, verifier, { leaseMs: 30_000 });
    await assert.rejects(() => forkPub.drainOnce(), /quarantine record conflict/);
    // the source row must NOT have been quarantined on a lying record
    assert.equal(Number((await pool.query('SELECT count(*)::int AS n FROM ha_outbox_rows WHERE stream_id=$1 AND quarantined_at IS NOT NULL', [sid])).rows[0].n), 0);
    assert.equal(await unacked(sid), 1);
  });

  await check('(R4) slow delivery + lease expiry/steal -> no double-apply, no loss, in order', async () => {
    const sid = 'sc:steal/v1'; await provision(sid); const N = 8;
    const ob = mkOutbox(serial, sid);
    for (let i = 0; i < N; i++) await ob.withOutboxTx((tx) => ob.appendInTx(tx, { streamId: sid, rawMutation: { pairId: 'p' + i }, fenceToken: 0n }));
    const receiver = new PgReceiverCheckpoint<Clean>(sid, sanitizer, applierRecording);
    const slow: OutboxTransport = { async deliverAndAwaitAck(record) {
      await new Promise((r) => setTimeout(r, 120)); // slow delivery > lease -> lease can be stolen mid-flight
      const d = await serial.transaction((e) => receiver.verifyAndApplyInTx(createBoundTx(e), record as OutboxRecord<Clean>));
      return receiptFor(record, d);
    } };
    const mkPub = () => new PgDurablePublisher<Clean>(serial, sid, slow, 'quarantine', sanitizer, verifier, { leaseMs: 100 }); // short lease
    const loop = async () => { for (let i = 0; i < 100; i++) { try { await mkPub().drainOnce(); } catch (e) { if (!/lease/i.test(String(e))) throw e; } if ((await unacked(sid)) === 0) break; await new Promise((r) => setTimeout(r, 15)); } };
    await Promise.all([loop(), loop()]);
    // idempotent receiver: each sequence applied EXACTLY once, in order, despite stolen leases + redelivery
    assert.deepEqual(appliedOrder, Array.from({ length: N }, (_, i) => i + 1), 'lease steal caused double-apply or out-of-order');
    assert.equal(await unacked(sid), 0, 'lease steal lost rows');
    assert.equal(Number((await pool.query('SELECT count(*)::int AS n FROM ha_outbox_quarantine WHERE stream_id=$1', [sid])).rows[0].n), 0);
  });

  console.log(`\n# ${passed} checks passed`);
}

main().then(() => pool.end()).then(() => process.exit(0)).catch(async (e) => { console.error('FAILED:', e); await pool.end().catch(() => {}); process.exit(1); });
