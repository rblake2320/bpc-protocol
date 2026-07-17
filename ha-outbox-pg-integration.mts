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
  PgPromotionFence,
  PgReceiverCheckpoint,
  adoptCurrentSchemaVersion,
  assertSchemaReady,
  attestSchema,
  canonicalOpDigest,
  ContractValidationError,
  provisionSchemaVersion,
  schemaManifest,
} from './packages/server/src/index.ts';
// version-only gate is intentionally NOT in the package index (weaker gate);
// imported from the module directly only to demonstrate the drift bypass.
import { assertSchemaVersionOnly } from './packages/server/src/ha-outbox-pg.ts';
import type { SchemaReadyToken } from './packages/server/src/index.ts';
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
const SCHEMA = 'public'; // the pinned schema all operations bind to
let READY: SchemaReadyToken; // set by resetSchema via provisionSchemaVersion

/** A transactor whose connections DEFAULT their search_path to a hostile schema,
 *  simulating a pooled connection that resolves unqualified names elsewhere. The
 *  impl must re-pin to its configured schema in every critical tx regardless. */
class EvilDefaultPg implements PgTransactor {
  constructor(private readonly evilSchema: string) {}
  async transaction<T>(fn: (exec: PgExecutor) => Promise<T>): Promise<T> {
    const client = await pool.connect();
    try {
      await client.query('BEGIN ISOLATION LEVEL SERIALIZABLE');
      await client.query(`SET LOCAL search_path TO ${this.evilSchema}`); // hostile default
      const exec: PgExecutor = { query: async (sql, params) => { const r = await client.query(sql, params as unknown[]); return { rows: r.rows, rowCount: r.rowCount ?? 0 }; } };
      const result = await fn(exec);
      await client.query('COMMIT');
      return result;
    } catch (e) { await client.query('ROLLBACK').catch(() => {}); throw e; } finally { client.release(); }
  }
}

// (R12) A conforming transactor: bounds queries (statement_timeout), VERIFIES the
// COMMIT command tag (an aborted tx silently turns COMMIT into ROLLBACK), and
// DISCARDS the connection on any error/timeout so a poisoned connection is never
// reused. (A production impl would also set a socket-level timeout.)
class RealPg implements PgTransactor {
  constructor(private readonly level: 'SERIALIZABLE' | 'READ COMMITTED') {}
  async transaction<T>(fn: (exec: PgExecutor) => Promise<T>): Promise<T> {
    for (let attempt = 0; ; attempt++) {
      const client = await pool.connect();
      let errored = false;
      try {
        await client.query(`BEGIN ISOLATION LEVEL ${this.level}`);
        await client.query("SET LOCAL statement_timeout = '30000'"); // bound queries at the connection layer
        const exec: PgExecutor = { query: async (sql, params) => { const r = await client.query(sql, params as unknown[]); return { rows: r.rows, rowCount: r.rowCount ?? 0 }; } };
        const result = await fn(exec);
        const c = await client.query('COMMIT');
        if ((c as { command?: string }).command !== 'COMMIT') { errored = true; throw new Error(`COMMIT did not commit (aborted tx -> ${(c as { command?: string }).command})`); }
        return result;
      } catch (e) {
        errored = true;
        await client.query('ROLLBACK').catch(() => {});
        const code = (e as { code?: string }).code;
        if ((code === '40001' || code === '40P01') && attempt < 50) continue; // finally discards; loop retries with a fresh client
        throw e;
      } finally {
        client.release(errored ? new Error('discard poisoned connection') : undefined);
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
const mkOutbox = (db: PgTransactor, streamId: string) => new PgDurableOutbox<Raw, Clean>(db, READY, { streamId, sanitizer, maxPendingRows: 100_000, backpressure: 'fail-authoritative-mutation' });

async function applyDDL(): Promise<void> {
  for (const stmt of HA_OUTBOX_PG_SCHEMA.split(';').map((s) => s.trim()).filter(Boolean)) await pool.query(stmt);
}
async function resetSchema(): Promise<void> {
  await pool.query('DROP SCHEMA IF EXISTS shadow CASCADE');
  await pool.query('DROP SCHEMA IF EXISTS evil CASCADE');
  await pool.query('DROP SCHEMA IF EXISTS alt CASCADE');
  await pool.query('DROP TABLE IF EXISTS ha_outbox_rows, ha_outbox_applied, ha_outbox_fence, ha_outbox_source_checkpoint, ha_outbox_receiver_checkpoint, ha_outbox_publisher_lease, ha_outbox_quarantine, ha_outbox_meta CASCADE');
  await pool.query('DROP FUNCTION IF EXISTS ha_noop() CASCADE');
  await applyDDL();
  READY = await provisionSchemaVersion(serial, SCHEMA); // attests fresh schema, stamps v2, mints token
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
  const receiver = new PgReceiverCheckpoint<Clean>(serial, streamId, sanitizer, applierRecording, READY);
  return {
    async deliverAndAwaitAck(record) {
      const decision = await receiver.verifyAndApplyDelivered(record as OutboxRecord<Clean>);
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
    await assertSchemaVersionOnly(serial, SCHEMA);
    await pool.query('UPDATE ha_outbox_meta SET schema_version = $1 WHERE id = 1', [HA_OUTBOX_SCHEMA_VERSION + 1]);
    await assert.rejects(() => assertSchemaVersionOnly(serial, SCHEMA), /schema version mismatch/);
  });

  await check('READ COMMITTED transactor is rejected; SERIALIZABLE works', async () => {
    const sid = 'sc:iso/v1'; await provision(sid);
    // readiness itself cannot be obtained on a non-serializable transactor
    await assert.rejects(() => assertSchemaReady(new RealPg('READ COMMITTED'), SCHEMA), /SERIALIZABLE/);
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
    const pubA = new PgDurablePublisher<Clean>(serial, sid, transport, 'quarantine', sanitizer, verifier, READY, { leaseMs: 30_000 });
    const pubB = new PgDurablePublisher<Clean>(serial, sid, transport, 'quarantine', sanitizer, verifier, READY, { leaseMs: 30_000 });
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
    const receiver = new PgReceiverCheckpoint<Clean>(serial, sid, sanitizer, applierRecording, READY);
    let deliveredByA = 0;
    // Publisher A: short lease, stops (throws) after delivering 4
    const transportA: OutboxTransport = { async deliverAndAwaitAck(record) {
      if (deliveredByA >= 4) throw new Error('publisher A stopped');
      deliveredByA++;
      const d = await receiver.verifyAndApplyDelivered(record as OutboxRecord<Clean>);
      decisions.push({ seq: record.sequence, decision: d });
      return receiptFor(record, d);
    } };
    const pubA = new PgDurablePublisher<Clean>(serial, sid, transportA, 'quarantine', sanitizer, verifier, READY, { leaseMs: 200 });
    await assert.rejects(() => pubA.drainOnce(), /publisher A stopped/);
    // wait for A's lease to expire, then B finishes the rest
    await new Promise((r) => setTimeout(r, 300));
    const transportB = receiverTransport(sid, decisions);
    // rebind B's receiver to the shared applied-order recorder (already global)
    const pubB = new PgDurablePublisher<Clean>(serial, sid, transportB, 'quarantine', sanitizer, verifier, READY, { leaseMs: 30_000 });
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
    const pub = new PgDurablePublisher<Clean>(serial, sid, transport, 'quarantine', sanitizer, verifier, READY, { leaseMs: 30_000 });
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
    const transientPub = new PgDurablePublisher<Clean>(serial, sid, { async deliverAndAwaitAck(r) { return receiptFor(r, 'reject-fence'); } }, 'quarantine', sanitizer, verifier, READY, { leaseMs: 30_000 });
    const t = await transientPub.drainOnce();
    assert.equal(t.acked, 0); assert.equal(t.retriable, true);
    assert.equal(await unacked(sid), 1, 'transient reject must not consume the row');
    // now deliver applied and confirm exactly-once
    const okPub = new PgDurablePublisher<Clean>(serial, sid, { async deliverAndAwaitAck(r) { return receiptFor(r, 'applied'); } }, 'quarantine', sanitizer, verifier, READY, { leaseMs: 30_000 });
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
    const applyWith = (rcv: PgReceiverCheckpoint<Clean>, r: OutboxRecord<Clean>) => rcv.verifyAndApplyDelivered(r);
    const r1 = new PgReceiverCheckpoint<Clean>(serial, sid, sanitizer, applierRecording, READY);
    assert.equal(await applyWith(r1, rec(1, { pairId: 'a' })), 'applied');
    assert.equal(await applyWith(r1, rec(2, { pairId: 'b' })), 'applied');
    const r2 = new PgReceiverCheckpoint<Clean>(serial, sid, sanitizer, applierRecording, READY); // restart
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
    await assert.rejects(() => adoptCurrentSchemaVersion(serial, SCHEMA), /attestation failed/, 'migration must not stamp a weakened schema');

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

  await check('(R8/HIGH) manifest catches trigger and RLS drift', async () => {
    await assertSchemaReady(serial, SCHEMA);
    // add a trigger -> attestation fails
    await pool.query('CREATE FUNCTION ha_noop() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$');
    await pool.query('CREATE TRIGGER ha_drift BEFORE INSERT ON ha_outbox_rows FOR EACH ROW EXECUTE FUNCTION ha_noop()');
    await assert.rejects(() => assertSchemaReady(serial, SCHEMA), /attestation failed/, 'an added trigger must fail attestation');
    // enable row-level security -> attestation fails
    await resetSchema(); await assertSchemaReady(serial, SCHEMA);
    await pool.query('ALTER TABLE ha_outbox_rows ENABLE ROW LEVEL SECURITY');
    await assert.rejects(() => assertSchemaReady(serial, SCHEMA), /attestation failed/, 'enabling RLS must fail attestation');
    // add an RLS policy -> attestation fails
    await resetSchema(); await assertSchemaReady(serial, SCHEMA);
    await pool.query('ALTER TABLE ha_outbox_rows ENABLE ROW LEVEL SECURITY');
    await pool.query('CREATE POLICY ha_pol ON ha_outbox_rows FOR SELECT USING (true)');
    await assert.rejects(() => assertSchemaReady(serial, SCHEMA), /attestation failed/);
  });

  await check('(R8/HIGH) readiness token is unforgeable + bound to transactor', async () => {
    const good = await assertSchemaReady(serial, SCHEMA);
    // a token minted for `serial` cannot construct a mechanism on a DIFFERENT transactor
    const other = new RealPg('SERIALIZABLE');
    assert.throws(() => new PgPromotionFence(other, good), /different PgTransactor/);
    // a forged (non-minted) object is rejected
    assert.throws(() => new PgPromotionFence(serial, {} as unknown as SchemaReadyToken), /forged or foreign/);
    // the correctly-bound token works
    const fence = new PgPromotionFence(serial, good);
    const t1 = await fence.acquire('r8:fence/v1'); const t2 = await fence.acquire('r8:fence/v1');
    assert.ok(t2 > t1);
  });

  await check('(R9/HIGH) a receiver cannot apply against a foreign-db tx (reject BEFORE any query)', async () => {
    const sid = 'sc:r9/v1'; await provision(sid);
    // receiverA is bound to `serial` (READY)
    const receiverA = new PgReceiverCheckpoint<Clean>(serial, sid, sanitizer, applierRecording, READY);
    // a token minted for `serial` cannot even CONSTRUCT a receiver on another transactor
    const serialB = new RealPg('SERIALIZABLE');
    assert.throws(() => new PgReceiverCheckpoint<Clean>(serialB, sid, sanitizer, applierRecording, READY), /different PgTransactor/);
    // and a bound tx produced by dbB cannot be fed to receiverA — rejected before any query runs
    const readyB = await assertSchemaReady(serialB, SCHEMA); // same physical DB, distinct transactor identity
    const outboxB = new PgDurableOutbox<Raw, Clean>(serialB, readyB, { streamId: sid, sanitizer, maxPendingRows: 100, backpressure: 'quarantine' });
    const dig = canonicalOpDigest<Clean>({ streamId: sid, sourceEpoch: 'e1', sequence: 1, fenceToken: '0', mutation: { pairId: 'x' } as SanitizedMutation<Clean> });
    const rec: OutboxRecord<Clean> = { contractVersion: '1', streamId: sid, sourceEpoch: 'e1', sequence: 1, fenceToken: '0', opDigest: dig, mutation: { pairId: 'x' } as SanitizedMutation<Clean> };
    let sawForeignTx = false;
    await assert.rejects(
      () => outboxB.withOutboxTx((txB) => { sawForeignTx = true; return receiverA.verifyAndApplyInTx(txB, rec); }),
      /bound to a different transactor/,
      'a foreign-db tx must be rejected by the receiver before any apply',
    );
    assert.equal(sawForeignTx, true);
    // nothing was applied
    assert.equal(Number((await pool.query('SELECT sequence FROM ha_outbox_receiver_checkpoint WHERE stream_id=$1', [sid])).rows[0].sequence), 0);
  });

  await check('(R10/HIGH) appendInTx + receiver reject foreign-db, wrong-schema, and retained (post commit/rollback) tx before any query', async () => {
    const sid = 'sc:r10/v1'; await provision(sid);
    const outbox = mkOutbox(serial, sid); // bound to (serial, public)
    const appendInput = { streamId: sid, rawMutation: { pairId: 'x' }, fenceToken: 0n };
    // (a) foreign transactor: a tx produced by dbB fed to outboxA -> reject before any query
    const serialB = new RealPg('SERIALIZABLE');
    const readyB = await assertSchemaReady(serialB, SCHEMA);
    const outboxB = new PgDurableOutbox<Raw, Clean>(serialB, readyB, { streamId: sid, sanitizer, maxPendingRows: 100, backpressure: 'quarantine' });
    await assert.rejects(() => outboxB.withOutboxTx((txB) => outbox.appendInTx(txB, appendInput)), /different transactor/);
    // (b) same db, DIFFERENT schema: provision the HA schema in `alt`, feed its tx to the public outbox
    const c = await pool.connect();
    await c.query('CREATE SCHEMA alt'); await c.query('SET search_path=alt');
    for (const s of HA_OUTBOX_PG_SCHEMA.split(';').map((x) => x.trim()).filter(Boolean)) await c.query(s);
    await c.query('RESET search_path'); // do NOT leak a session search_path back into the pool
    c.release();
    const readyAlt = await provisionSchemaVersion(serial, 'alt'); // attest + stamp the alt schema, mint its token
    const outboxAlt = new PgDurableOutbox<Raw, Clean>(serial, readyAlt, { streamId: sid, sanitizer, maxPendingRows: 100, backpressure: 'quarantine' });
    await assert.rejects(() => outboxAlt.withOutboxTx((txAlt) => outbox.appendInTx(txAlt, appendInput)), /different schema/);
    // (c) retained AFTER COMMIT: a handle kept past a successful tx is revoked
    let retained: any;
    await outbox.withOutboxTx(async (tx) => { retained = tx; return outbox.appendInTx(tx, { streamId: sid, rawMutation: { pairId: 'ok1' }, fenceToken: 0n }); });
    await assert.rejects(() => outbox.appendInTx(retained, appendInput), /not bound to a PostgreSQL transaction|forged or foreign/);
    // (d) retained AFTER ROLLBACK: a handle kept from a failed tx is revoked
    let retained2: any;
    await assert.rejects(() => outbox.withOutboxTx(async (tx) => { retained2 = tx; throw new Error('boom'); }), /boom/);
    await assert.rejects(() => outbox.appendInTx(retained2, appendInput), /not bound to a PostgreSQL transaction|forged or foreign/);
    // (e) the receiver rejects a retained tx too (before any apply)
    const rcv = new PgReceiverCheckpoint<Clean>(serial, sid, sanitizer, applierRecording, READY);
    const dig = canonicalOpDigest<Clean>({ streamId: sid, sourceEpoch: 'e1', sequence: 1, fenceToken: '0', mutation: { pairId: 'x' } as SanitizedMutation<Clean> });
    const rec: OutboxRecord<Clean> = { contractVersion: '1', streamId: sid, sourceEpoch: 'e1', sequence: 1, fenceToken: '0', opDigest: dig, mutation: { pairId: 'x' } as SanitizedMutation<Clean> };
    await assert.rejects(() => rcv.verifyAndApplyInTx(retained, rec), /not bound to a PostgreSQL transaction|forged or foreign/);
    // sanity: only the one legitimately-committed row exists; no foreign/stale op landed
    assert.equal(Number((await pool.query('SELECT count(*)::int AS n FROM ha_outbox_rows WHERE stream_id=$1', [sid])).rows[0].n), 1);
  });

  await check('(R5) DDL never auto-bumps meta; only attested migration advances', async () => {
    await pool.query('UPDATE ha_outbox_meta SET schema_version = 1 WHERE id = 1');
    await applyDDL();
    assert.equal(Number((await pool.query('SELECT schema_version FROM ha_outbox_meta WHERE id=1')).rows[0].schema_version), 1, 'DDL must NOT auto-bump an existing meta row');
    await assert.rejects(() => assertSchemaVersionOnly(serial, SCHEMA), /schema version mismatch/);
    await adoptCurrentSchemaVersion(serial, SCHEMA); // attests OK -> advances
    assert.equal(Number((await pool.query('SELECT schema_version FROM ha_outbox_meta WHERE id=1')).rows[0].schema_version), HA_OUTBOX_SCHEMA_VERSION);
    await assertSchemaVersionOnly(serial, SCHEMA);
  });

  await check('(R6/HIGH1) migration is forward-only: a FUTURE version is never downgraded, data preserved', async () => {
    const sid = 'sc:nodown/v1'; await provision(sid);
    const ob = mkOutbox(serial, sid);
    await ob.withOutboxTx((tx) => ob.appendInTx(tx, { streamId: sid, rawMutation: { pairId: 'keepme' }, fenceToken: 0n }));
    // simulate a future version sharing this exact catalog (semantic-only revision / pre-staged marker)
    await pool.query('UPDATE ha_outbox_meta SET schema_version = 3 WHERE id = 1');
    await assert.rejects(() => adoptCurrentSchemaVersion(serial, SCHEMA), /refusing to downgrade/);
    assert.equal(Number((await pool.query('SELECT schema_version FROM ha_outbox_meta WHERE id=1')).rows[0].schema_version), 3, 'future version must be preserved');
    assert.equal(Number((await pool.query('SELECT count(*)::int AS n FROM ha_outbox_rows WHERE stream_id=$1', [sid])).rows[0].n), 1, 'data must be preserved on refused downgrade');
    // being already-current is a clean no-op
    await pool.query('UPDATE ha_outbox_meta SET schema_version = $1 WHERE id = 1', [HA_OUTBOX_SCHEMA_VERSION]);
    await adoptCurrentSchemaVersion(serial, SCHEMA);
    assert.equal(Number((await pool.query('SELECT schema_version FROM ha_outbox_meta WHERE id=1')).rows[0].schema_version), HA_OUTBOX_SCHEMA_VERSION);
  });

  await check('(R7/HIGH1) operations bind to the configured schema even under a hostile pooled search_path', async () => {
    // good HA schema lives in public (SCHEMA); a malformed same-name set lives in evil
    await pool.query('CREATE SCHEMA evil');
    await pool.query('CREATE TABLE evil.ha_outbox_rows (bogus int)');
    const sid = 'sc:pin/v1'; await provision(sid);
    // a publisher whose CONNECTIONS default search_path to evil, but configured schema = public
    const evilDb = new EvilDefaultPg('evil');
    const evilReady = await assertSchemaReady(evilDb, SCHEMA); // pins to public despite the evil default; token bound to evilDb
    const boundOutbox = new PgDurableOutbox<Raw, Clean>(evilDb, evilReady, { streamId: sid, sanitizer, maxPendingRows: 100, backpressure: 'quarantine' });
    // the append must land in PUBLIC (the pinned schema), not evil — proven by the row appearing in public
    const h = await boundOutbox.withOutboxTx((tx) => boundOutbox.appendInTx(tx, { streamId: sid, rawMutation: { pairId: 'p0' }, fenceToken: 0n }));
    assert.equal(h.sequence, 1);
    assert.equal(Number((await pool.query('SELECT count(*)::int AS n FROM public.ha_outbox_rows WHERE stream_id=$1', [sid])).rows[0].n), 1, 'operation must bind to the pinned schema, not the hostile default');
    // readiness for the good schema does not make an operation configured for evil pass
    await assertSchemaReady(serial, SCHEMA); // public is ready
    await assert.rejects(() => assertSchemaReady(serial, 'evil'), /attestation failed|schema context/, 'readiness must be per-configured-schema and fail closed for a malformed schema');
    // a configured schema that does not exist fails closed (no silent fallback)
    await assert.rejects(() => assertSchemaReady(serial, 'nonexistent_schema'), /schema context mismatch/);
  });

  await check('(R6/HIGH2) assertSchemaReady catches post-stamp structural drift (version-only check does not)', async () => {
    await assertSchemaReady(serial, SCHEMA); // fresh + stamped -> ready
    // validly stamped v2, then drop a CHECK while leaving meta = 2
    await pool.query(`DO $$ DECLARE r record; BEGIN
      FOR r IN SELECT conname FROM pg_constraint c JOIN pg_class rel ON rel.oid=c.conrelid
               WHERE rel.relname='ha_outbox_rows' AND c.contype='c' AND pg_get_constraintdef(c.oid) LIKE '%op_digest%'
      LOOP EXECUTE 'ALTER TABLE ha_outbox_rows DROP CONSTRAINT '||quote_ident(r.conname); END LOOP; END $$;`);
    assert.equal(Number((await pool.query('SELECT schema_version FROM ha_outbox_meta WHERE id=1')).rows[0].schema_version), HA_OUTBOX_SCHEMA_VERSION);
    await assertSchemaVersionOnly(serial, SCHEMA); // version-only check still passes (the bypass)
    await assert.rejects(() => assertSchemaReady(serial, SCHEMA), /attestation failed/, 'readiness gate must catch structural drift');
    // dropping a table too
    await resetSchema();
    await assertSchemaReady(serial, SCHEMA);
    await pool.query('DROP INDEX ha_outbox_rows_deliverable');
    await assert.rejects(() => assertSchemaReady(serial, SCHEMA), /attestation failed/);
  });

  await check('(R5/HIGH2) quarantine conflict with a mismatched preexisting row fails closed', async () => {
    const sid = 'sc:qconf/v1'; await provision(sid);
    const ob = mkOutbox(serial, sid);
    await ob.withOutboxTx((tx) => ob.appendInTx(tx, { streamId: sid, rawMutation: { pairId: 'p0' }, fenceToken: 0n }));
    // plant a LYING quarantine row for (sid,e1,1): different digest + different decision
    await pool.query("INSERT INTO ha_outbox_quarantine (stream_id, source_epoch, sequence, op_digest, decision) VALUES ($1,'e1',1,$2,'reject-stale')", [sid, 'b'.repeat(64)]);
    const forkPub = new PgDurablePublisher<Clean>(serial, sid, { async deliverAndAwaitAck(r) { return receiptFor(r, 'reject-fork'); } }, 'quarantine', sanitizer, verifier, READY, { leaseMs: 30_000 });
    await assert.rejects(() => forkPub.drainOnce(), /quarantine record conflict/);
    // the source row must NOT have been quarantined on a lying record
    assert.equal(Number((await pool.query('SELECT count(*)::int AS n FROM ha_outbox_rows WHERE stream_id=$1 AND quarantined_at IS NOT NULL', [sid])).rows[0].n), 0);
    assert.equal(await unacked(sid), 1);
  });

  await check('(R4) slow delivery + lease expiry/steal -> no double-apply, no loss, in order', async () => {
    const sid = 'sc:steal/v1'; await provision(sid); const N = 8;
    const ob = mkOutbox(serial, sid);
    for (let i = 0; i < N; i++) await ob.withOutboxTx((tx) => ob.appendInTx(tx, { streamId: sid, rawMutation: { pairId: 'p' + i }, fenceToken: 0n }));
    const receiver = new PgReceiverCheckpoint<Clean>(serial, sid, sanitizer, applierRecording, READY);
    const slow: OutboxTransport = { async deliverAndAwaitAck(record) {
      await new Promise((r) => setTimeout(r, 120)); // slow delivery > lease -> lease can be stolen mid-flight
      const d = await receiver.verifyAndApplyDelivered(record as OutboxRecord<Clean>);
      return receiptFor(record, d);
    } };
    const mkPub = () => new PgDurablePublisher<Clean>(serial, sid, slow, 'quarantine', sanitizer, verifier, READY, { leaseMs: 100 }); // short lease
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
