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
  PgPairMutationApplier,
  PgTransactionalPairStore,
  bpcPairMutationSanitizer,
  NodePostgresTransactor,
  adoptCurrentSchemaVersion,
  assertSchemaReady,
  attestSchema,
  canonicalOpDigest,
  ContractValidationError,
  migrateLegacyPairAuthorityToV3,
  prepareLegacyPairAuthorityV2ForMigration,
  provisionSchemaVersion,
  schemaManifest,
  successfulUsePolicy,
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
  BpcPairMutation,
  StoredPair,
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

const serial = new NodePostgresTransactor(pool, { maxSerializationRetries: 50 });

/** Deliberately nonconforming negative-test adapter. Production uses
 * NodePostgresTransactor above; this exists only to prove the mechanism rejects
 * READ COMMITTED at its runtime assertion. */
const readCommitted: PgTransactor = {
  async transaction<T>(fn: (exec: PgExecutor) => Promise<T>): Promise<T> {
    const client = await pool.connect();
    try {
      await client.query('BEGIN ISOLATION LEVEL READ COMMITTED');
      const exec: PgExecutor = { query: async (sql, params) => { const r = await client.query(sql, params as unknown[]); return { rows: r.rows, rowCount: r.rowCount ?? 0 }; } };
      const value = await fn(exec);
      await client.query('COMMIT');
      return value;
    } catch (error) {
      await client.query('ROLLBACK').catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  },
};

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
async function installLegacyPairSchema(standalone=false): Promise<void> {
  await pool.query(`DROP TABLE IF EXISTS bpc_pending,bpc_pairs${standalone?',ha_outbox_rows,ha_outbox_applied,ha_outbox_fence,ha_outbox_source_checkpoint,ha_outbox_receiver_checkpoint,ha_outbox_publisher_lease,ha_outbox_quarantine,ha_outbox_meta':''} CASCADE`);
  await pool.query(`CREATE TABLE bpc_pairs (
    id text PRIMARY KEY, name text NOT NULL, scope text NOT NULL, mode text NOT NULL,
    secret_hash text NOT NULL, pub_jwk jsonb NOT NULL, status text NOT NULL DEFAULT 'active',
    created bigint NOT NULL, last_active bigint, requests integer NOT NULL DEFAULT 0,
    failed_sigs integer NOT NULL DEFAULT 0, cumulative_failures double precision,
    first_failure_at bigint, max_requests bigint, kind text NOT NULL DEFAULT 'legitimate',
    canary_class text, expires_at bigint
  )`);
  await pool.query('CREATE TABLE bpc_pending (token text PRIMARY KEY, registration jsonb NOT NULL, requested_at bigint NOT NULL)');
  if(!standalone)await pool.query('UPDATE ha_outbox_meta SET schema_version=2 WHERE id=1');
}
async function resetSchema(): Promise<void> {
  await pool.query('DROP SCHEMA IF EXISTS shadow CASCADE');
  await pool.query('DROP SCHEMA IF EXISTS evil CASCADE');
  await pool.query('DROP SCHEMA IF EXISTS alt CASCADE');
  await pool.query('DROP SCHEMA IF EXISTS replica CASCADE');
  await pool.query('DROP TABLE IF EXISTS bpc_pending, bpc_pairs, ha_outbox_rows, ha_outbox_applied, ha_outbox_fence, ha_outbox_source_checkpoint, ha_outbox_receiver_checkpoint, ha_outbox_publisher_lease, ha_outbox_quarantine, ha_outbox_meta CASCADE');
  await pool.query('DROP FUNCTION IF EXISTS ha_noop() CASCADE');
  await applyDDL();
  READY = await provisionSchemaVersion(serial, SCHEMA); // attests fresh schema, stamps current version, mints token
}
async function provision(streamId: string, epoch = 'e1'): Promise<void> {
  await pool.query('INSERT INTO ha_outbox_fence (stream_id, fence_token) VALUES ($1,0)', [streamId]);
  await pool.query('INSERT INTO ha_outbox_source_checkpoint (stream_id, source_epoch, sequence) VALUES ($1,$2,0)', [streamId, epoch]);
  await pool.query('INSERT INTO ha_outbox_receiver_checkpoint (stream_id, source_epoch, sequence) VALUES ($1,$2,0)', [streamId, epoch]);
}
async function applyDDLInSchema(schema: string): Promise<void> {
  if (!/^[a-z][a-z0-9_]{0,62}$/.test(schema)) throw new Error('invalid test schema');
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`SET LOCAL search_path TO ${schema}`);
    for (const stmt of HA_OUTBOX_PG_SCHEMA.split(';').map((s) => s.trim()).filter(Boolean)) await client.query(stmt);
    await client.query('COMMIT');
  } catch (error) { await client.query('ROLLBACK').catch(() => {}); throw error; } finally { client.release(); }
}
async function provisionInSchema(schema: string, streamId: string, epoch = 'e1'): Promise<void> {
  await pool.query(`INSERT INTO ${schema}.ha_outbox_fence (stream_id, fence_token) VALUES ($1,0)`, [streamId]);
  await pool.query(`INSERT INTO ${schema}.ha_outbox_source_checkpoint (stream_id, source_epoch, sequence) VALUES ($1,$2,0)`, [streamId, epoch]);
  await pool.query(`INSERT INTO ${schema}.ha_outbox_receiver_checkpoint (stream_id, source_epoch, sequence) VALUES ($1,$2,0)`, [streamId, epoch]);
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
    await assert.rejects(() => assertSchemaReady(readCommitted, SCHEMA), /SERIALIZABLE/);
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
      FOR r IN SELECT conname FROM pg_constraint c JOIN pg_class rel ON rel.oid=c.conrelid JOIN pg_namespace n ON n.oid=rel.relnamespace
               WHERE n.nspname=current_schema() AND rel.relname='ha_outbox_rows' AND c.contype='c' AND pg_get_constraintdef(c.oid) LIKE '%op_digest%'
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
    const other = new NodePostgresTransactor(pool);
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
    const serialB = new NodePostgresTransactor(pool);
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
    const serialB = new NodePostgresTransactor(pool);
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

  await check('(v2->v3) legacy pair authority migrates atomically, preserves data, attests, and advances only after validation', async () => {
    await installLegacyPairSchema(true);
    const jwk = { kty:'EC', crv:'P-256', x:'x'.repeat(42)+'w', y:'y'.repeat(42)+'w' };
    await pool.query(`INSERT INTO bpc_pairs(id,name,scope,mode,secret_hash,pub_jwk,status,created,last_active,requests,failed_sigs,cumulative_failures,kind)
      VALUES('legacy_pair','Legacy','read-write','production',$1,$2,'active',1,NULL,2,1,1.25,'legitimate')`, ['s'.repeat(43), jwk]);
    await pool.query(`INSERT INTO bpc_pending(token,registration,requested_at) VALUES('legacy_pending',$1,10)`, [{name:'Legacy',scope:'read-write',mode:'production',secretHash:'s'.repeat(43),pubJwk:jwk,kind:'legitimate'}]);
    await prepareLegacyPairAuthorityV2ForMigration(serial,SCHEMA);
    const migrated = await migrateLegacyPairAuthorityToV3(serial, SCHEMA);
    assert.ok(migrated, 'migration did not return a readiness capability');
    await assertSchemaReady(serial, SCHEMA);
    assert.equal(Number((await pool.query("SELECT cumulative_failures FROM bpc_pairs WHERE id='legacy_pair'")).rows[0].cumulative_failures), 1.25);
    assert.equal(Number((await pool.query("SELECT requested_at FROM bpc_pending WHERE token='legacy_pending'")).rows[0].requested_at), 10);
    assert.equal(Number((await pool.query('SELECT schema_version FROM ha_outbox_meta WHERE id=1')).rows[0].schema_version), HA_OUTBOX_SCHEMA_VERSION);
  });

  await check('(v2->v3) migration lock precedes the SERIALIZABLE snapshot so a blocked writer can never be lost', async () => {
    await resetSchema(); await installLegacyPairSchema();
    const writer = await pool.connect();
    const jwk = { kty:'EC', crv:'P-256', x:'x'.repeat(42)+'w', y:'y'.repeat(42)+'w' };
    try {
      await writer.query('BEGIN');
      await writer.query(`INSERT INTO bpc_pairs(id,name,scope,mode,secret_hash,pub_jwk,status,created,last_active,requests,failed_sigs,kind)
        VALUES('late','Late','read','production',$1,$2,'active',1,NULL,0,0,'legitimate')`, ['s'.repeat(43), jwk]);
      const migration = migrateLegacyPairAuthorityToV3(serial, SCHEMA);
      let waiting = false;
      for (let i=0; i<100 && !waiting; i++) {
        const result = await pool.query(`SELECT EXISTS(
          SELECT 1 FROM pg_locks
          WHERE relation='public.bpc_pairs'::regclass
            AND mode='AccessExclusiveLock' AND NOT granted
        ) AS waiting`);
        waiting = result.rows[0]?.waiting === true;
        if (!waiting) await new Promise((resolve) => setTimeout(resolve, 10));
      }
      assert.equal(waiting, true, 'migration did not block on the writer-held authority table');
      await writer.query('COMMIT');
      let migrationError: unknown;
      try { await migration; } catch (error) { migrationError = error; }
      const lateRows = Number((await pool.query("SELECT count(*)::int AS n FROM bpc_pairs WHERE id='late'")).rows[0].n);
      assert.equal(lateRows, 1, 'migration lost a row committed while its authority lock was waiting');
      const version = Number((await pool.query('SELECT schema_version FROM ha_outbox_meta WHERE id=1')).rows[0].schema_version);
      if (migrationError) assert.equal(version, 2, 'failed migration advanced the schema authority');
      else assert.equal(version, HA_OUTBOX_SCHEMA_VERSION, 'successful migration did not advance the schema authority');
    } finally {
      await writer.query('ROLLBACK').catch(()=>{});
      writer.release();
    }
  });

  await check('(v2->v3) invalid legacy authority fails closed with data and version marker preserved', async () => {
    await resetSchema(); await installLegacyPairSchema();
    await pool.query(`INSERT INTO bpc_pairs(id,name,scope,mode,secret_hash,pub_jwk,status,created,last_active,requests,failed_sigs,kind)
      VALUES('bad_private','Bad','read','production',$1,$2,'active',1,NULL,0,0,'legitimate')`, ['s'.repeat(43), {kty:'EC',crv:'P-256',x:'x'.repeat(42)+'w',y:'y'.repeat(42)+'w',d:'private'}]);
    await assert.rejects(() => migrateLegacyPairAuthorityToV3(serial, SCHEMA), /check constraint|violates/i);
    assert.equal(Number((await pool.query('SELECT schema_version FROM ha_outbox_meta WHERE id=1')).rows[0].schema_version), 2);
    assert.equal(Number((await pool.query("SELECT count(*)::int n FROM bpc_pairs WHERE id='bad_private'")).rows[0].n), 1, 'failed migration lost legacy authority data');
    const type = (await pool.query("SELECT udt_name FROM information_schema.columns WHERE table_schema='public' AND table_name='bpc_pairs' AND column_name='requests'")).rows[0].udt_name;
    assert.equal(type, 'int4', 'failed migration partially swapped the legacy table');
    for (const [name, seed] of [
      ['unsafe integer', () => pool.query(`INSERT INTO bpc_pairs(id,name,scope,mode,secret_hash,pub_jwk,status,created,last_active,requests,failed_sigs,kind) VALUES('unsafe','x','read','production',$1,$2,'active',$3,NULL,0,0,'legitimate')`,['s'.repeat(43),{kty:'EC',crv:'P-256',x:'x'.repeat(42)+'w',y:'y'.repeat(42)+'w'},'9007199254740992'])],
      ['non-finite float', () => pool.query(`INSERT INTO bpc_pairs(id,name,scope,mode,secret_hash,pub_jwk,status,created,last_active,requests,failed_sigs,cumulative_failures,kind) VALUES('nan_pair','x','read','production',$1,$2,'active',1,NULL,0,0,'NaN','legitimate')`,['s'.repeat(43),{kty:'EC',crv:'P-256',x:'x'.repeat(42)+'w',y:'y'.repeat(42)+'w'}])],
      ['malformed pending registration', () => pool.query("INSERT INTO bpc_pending(token,registration,requested_at) VALUES('bad_pending',$1,1)",[{name:'x',scope:'read',mode:'production',secretHash:'s'.repeat(43),pubJwk:{}}])],
    ] as const) {
      await resetSchema(); await installLegacyPairSchema(); await seed();
      await assert.rejects(()=>migrateLegacyPairAuthorityToV3(serial,SCHEMA),/check constraint|violates/i,name);
      assert.equal(Number((await pool.query('SELECT schema_version FROM ha_outbox_meta WHERE id=1')).rows[0].schema_version),2,`${name} advanced the version marker`);
    }
    await resetSchema();
  });

  await check('(v2->v3) FORCE RLS cannot hide authority rows from migration', async () => {
    const role=`bpc_migrator_${process.pid}`, schema=`rls_migration_${process.pid}`, password='migration-test-only';
    await pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`); await pool.query(`DROP ROLE IF EXISTS ${role}`);
    await pool.query(`CREATE ROLE ${role} LOGIN PASSWORD '${password}' NOSUPERUSER NOBYPASSRLS`);
    await pool.query(`CREATE SCHEMA ${schema} AUTHORIZATION ${role}`);
    const roleUrl=new URL(connectionString); roleUrl.username=role; roleUrl.password=password;
    const rolePool=new Pool({connectionString:roleUrl.toString(),max:2});
    try {
      const client=await rolePool.connect();
      try { await client.query(`SET search_path TO ${schema}`); for(const stmt of HA_OUTBOX_PG_SCHEMA.split(';').map(s=>s.trim()).filter(Boolean))await client.query(stmt); await client.query('INSERT INTO ha_outbox_meta(id,schema_version) VALUES(1,2)'); await client.query('DROP TABLE bpc_pending,bpc_pairs'); await client.query(`CREATE TABLE bpc_pairs(id text PRIMARY KEY,name text NOT NULL,scope text NOT NULL,mode text NOT NULL,secret_hash text NOT NULL,pub_jwk jsonb NOT NULL,status text NOT NULL DEFAULT 'active',created bigint NOT NULL,last_active bigint,requests integer NOT NULL DEFAULT 0,failed_sigs integer NOT NULL DEFAULT 0,cumulative_failures double precision,first_failure_at bigint,max_requests bigint,kind text NOT NULL DEFAULT 'legitimate',canary_class text,expires_at bigint);CREATE TABLE bpc_pending(token text PRIMARY KEY,registration jsonb NOT NULL,requested_at bigint NOT NULL)`); const jwk={kty:'EC',crv:'P-256',x:'x'.repeat(42)+'w',y:'y'.repeat(42)+'w'}; for(const id of ['visible','hidden'])await client.query(`INSERT INTO bpc_pairs(id,name,scope,mode,secret_hash,pub_jwk,status,created,last_active,requests,failed_sigs,kind) VALUES($1,'x','read','production',$2,$3,'active',1,NULL,0,0,'legitimate')`,[id,'s'.repeat(43),jwk]); await client.query('ALTER TABLE bpc_pairs ENABLE ROW LEVEL SECURITY'); await client.query('ALTER TABLE bpc_pairs FORCE ROW LEVEL SECURITY'); await client.query("CREATE POLICY visible_only ON bpc_pairs USING(id='visible')"); }
      finally { client.release(); }
      const roleDb=new NodePostgresTransactor(rolePool);
      await assert.rejects(()=>migrateLegacyPairAuthorityToV3(roleDb,schema),/unsafe relation\/RLS\/policy/);
      assert.equal(Number((await pool.query(`SELECT count(*)::int n FROM ${schema}.bpc_pairs`)).rows[0].n),2,'RLS migration lost a hidden authority row');
      assert.equal(Number((await pool.query(`SELECT schema_version FROM ${schema}.ha_outbox_meta WHERE id=1`)).rows[0].schema_version),2);
    } finally { await rolePool.end().catch(()=>{}); await pool.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`); await pool.query(`DROP ROLE IF EXISTS ${role}`); }
  });

  await check('(R6/HIGH1) migration is forward-only: a FUTURE version is never downgraded, data preserved', async () => {
    const sid = 'sc:nodown/v1'; await provision(sid);
    const ob = mkOutbox(serial, sid);
    await ob.withOutboxTx((tx) => ob.appendInTx(tx, { streamId: sid, rawMutation: { pairId: 'keepme' }, fenceToken: 0n }));
    // simulate a future version sharing this exact catalog (semantic-only revision / pre-staged marker)
    await pool.query('UPDATE ha_outbox_meta SET schema_version = $1 WHERE id = 1', [HA_OUTBOX_SCHEMA_VERSION + 1]);
    await assert.rejects(() => adoptCurrentSchemaVersion(serial, SCHEMA), /refusing to downgrade/);
    assert.equal(Number((await pool.query('SELECT schema_version FROM ha_outbox_meta WHERE id=1')).rows[0].schema_version), HA_OUTBOX_SCHEMA_VERSION + 1, 'future version must be preserved');
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

  await check('(pair authority) all PairStore writes commit atomically with ordered outbox and apply on an independent receiver', async () => {
    const sid = 'bpc:pair:default/v1'; await provision(sid);
    await pool.query('CREATE SCHEMA replica');
    await applyDDLInSchema('replica');
    const replicaReady = await provisionSchemaVersion(serial, 'replica');
    await provisionInSchema('replica', sid);

    const sealKey = Buffer.alloc(32, 7);
    const keyring = { activeKeyId:'pair-key-1', resolveKey:(keyId:string) => { if (keyId !== 'pair-key-1') throw new Error('unknown key'); return sealKey; } };
    const source = new PgTransactionalPairStore(serial, READY, { streamId: sid, fenceToken: 0n, keyring, maxPendingRows: 100 });
    const receiver = new PgReceiverCheckpoint<BpcPairMutation>(serial, sid, bpcPairMutationSanitizer, new PgPairMutationApplier(sid, keyring), replicaReady);
    const decisions: ReceiverDecision[] = [];
    const transport: OutboxTransport = { async deliverAndAwaitAck(record) {
      const decision = await receiver.verifyAndApplyDelivered(record as OutboxRecord<BpcPairMutation>);
      decisions.push(decision); return receiptFor(record, decision);
    } };
    const publisher = new PgDurablePublisher<BpcPairMutation>(serial, sid, transport, 'fail-authoritative-mutation', bpcPairMutationSanitizer, verifier, READY, { leaseMs: 30_000 });
    const pair: StoredPair = {
      id: 'pair_atomic_1', name: 'Atomic pair', scope: 'read-write', mode: 'production',
      secretHash: 's'.repeat(43), pubJwk: { kty: 'EC', crv: 'P-256', x: 'x'.repeat(42)+'w', y: 'y'.repeat(42)+'w' },
      status: 'active', created: 100, lastActive: null, requests: 2, failedSigs: 1,
      cumulativeFailures: 1.25e-7, firstFailureAt: 90, maxRequests: 1000, kind: 'legitimate', expiresAt: 5000,
    };
    const registration = { name: pair.name, scope: pair.scope, mode: pair.mode, secretHash: pair.secretHash, pubJwk: pair.pubJwk, maxRequests: pair.maxRequests, kind: pair.kind };

    await source.set(pair); assert.equal((await source.get(pair.id))?.cumulativeFailures, 1.25e-7);
    const storedWire = (await pool.query('SELECT mutation FROM ha_outbox_rows WHERE stream_id=$1 AND sequence=1', [sid])).rows[0].mutation;
    assert.equal(storedWire.kind, 'bpc.pair.set.v1'); assert.ok(storedWire.sealed?.ciphertext);
    assert.ok(!JSON.stringify(storedWire).includes(pair.secretHash), 'outbox leaked the operational HMAC key');
    assert.ok(!JSON.stringify(storedWire).includes('secretHash'), 'outbox leaked a clear secretHash field');
    assert.equal((await publisher.drainOnce()).acked, 1);
    assert.equal(Number((await pool.query('SELECT cumulative_failures FROM replica.bpc_pairs WHERE id=$1', [pair.id])).rows[0].cumulative_failures), 1.25e-7);

    await source.setPending('pending-1', registration, 200); assert.equal((await publisher.drainOnce()).acked, 1);
    assert.equal(Number((await pool.query("SELECT count(*)::int n FROM replica.bpc_pending WHERE token='pending-1'")).rows[0].n), 1);
    await source.deletePending('pending-1'); assert.equal((await publisher.drainOnce()).acked, 1);
    assert.equal(Number((await pool.query("SELECT count(*)::int n FROM replica.bpc_pending WHERE token='pending-1'")).rows[0].n), 0);
    await source.delete(pair.id); assert.equal((await publisher.drainOnce()).acked, 1);
    assert.equal(Number((await pool.query('SELECT count(*)::int n FROM replica.bpc_pairs WHERE id=$1', [pair.id])).rows[0].n), 0);
    assert.deepEqual(decisions, ['applied', 'applied', 'applied', 'applied']);
    assert.equal(Number((await pool.query('SELECT sequence FROM ha_outbox_source_checkpoint WHERE stream_id=$1', [sid])).rows[0].sequence), 4);
    assert.equal(Number((await pool.query('SELECT sequence FROM replica.ha_outbox_receiver_checkpoint WHERE stream_id=$1', [sid])).rows[0].sequence), 4);
  });

  await check('(atomic registry) approval, capacity, mutation, usage claim, and receiver compound apply are serialized', async () => {
    const sid='bpc:pair:registry/v1';await provision(sid);await pool.query('CREATE SCHEMA replica');await applyDDLInSchema('replica');const replicaReady=await provisionSchemaVersion(serial,'replica');await provisionInSchema('replica',sid);
    const keyring={activeKeyId:'pair-key-1',resolveKey:()=>Buffer.alloc(32,9)};
    const source=new PgTransactionalPairStore(serial,READY,{streamId:sid,fenceToken:0n,keyring,maxPendingRows:100});
    const receiver=new PgReceiverCheckpoint<BpcPairMutation>(serial,sid,bpcPairMutationSanitizer,new PgPairMutationApplier(sid,keyring),replicaReady);
    const transport:OutboxTransport={async deliverAndAwaitAck(record){const d=await receiver.verifyAndApplyDelivered(record as OutboxRecord<BpcPairMutation>);return receiptFor(record,d);}};
    const publisher=new PgDurablePublisher<BpcPairMutation>(serial,sid,transport,'fail-authoritative-mutation',bpcPairMutationSanitizer,verifier,READY,{leaseMs:30_000});
    const jwk={kty:'EC',crv:'P-256',x:'x'.repeat(42)+'w',y:'y'.repeat(42)+'w'} as JsonWebKey;
    const registration={name:'approved',scope:'read' as const,mode:'production' as const,secretHash:'s'.repeat(43),pubJwk:jwk,maxRequests:1,kind:'legitimate' as const};
    await source.setPending('approve-1',registration,100);
    const pair:StoredPair={id:'approved_pair',...registration,status:'active',created:101,lastActive:null,requests:0,failedSigs:0};
    const approvals=await Promise.all([source.approvePending('approve-1',{registration,requestedAt:100},pair,1),source.approvePending('approve-1',{registration,requestedAt:100},pair,1)]);
    assert.deepEqual(approvals.sort(),[false,true]);
    assert.equal((await source.getPending('approve-1')),undefined);
    assert.equal((await source.get(pair.id))?.status,'active');
    while((await publisher.drainOnce()).attempted>0){}
    assert.equal(Number((await pool.query("SELECT count(*)::int n FROM replica.bpc_pending WHERE token='approve-1'")).rows[0].n),0);
    assert.equal(Number((await pool.query("SELECT count(*)::int n FROM replica.bpc_pairs WHERE id='approved_pair'")).rows[0].n),1);

    await Promise.all([
      source.atomicMutate(pair.id,(current)=>({...current,name:'renamed'})),
      source.atomicMutate(pair.id,(current)=>({...current,scope:'admin'})),
    ]);
    assert.deepEqual(((await source.get(pair.id))&&{name:(await source.get(pair.id))!.name,scope:(await source.get(pair.id))!.scope}),{name:'renamed',scope:'admin'});
    await source.atomicMutate(pair.id,(current)=>({...current,expiresAt:100,failedSigs:10}));
    await source.atomicMutate(pair.id,(current)=>({...current,expiresAt:10_000,failedSigs:0}));
    assert.equal(await source.expireIfElapsed(pair.id,500),false,'stale expiry fact expired a freshly extended pair');
    assert.equal(await source.lockIfFailureThreshold(pair.id,10),false,'stale failure threshold locked a freshly reset pair');
    assert.equal((await source.get(pair.id))?.status,'active');
    const claimPolicy=successfulUsePolicy((await source.get(pair.id))!);
    const claims=await Promise.all([source.claimSuccessfulUse(pair.id,200,claimPolicy),source.claimSuccessfulUse(pair.id,201,claimPolicy)]);
    assert.equal(claims.filter((outcome)=>outcome==='claimed').length,1);assert.equal(claims.filter((outcome)=>outcome==='usage-exhausted').length,1);
    const claimedPair=await source.get(pair.id);assert.equal(claimedPair?.requests,1);assert.equal(claimedPair?.status,'expired');assert.equal(claimedPair?.lastActive,claims[0]==='claimed'?200:201);

    const r2={...registration,name:'second'},r3={...registration,name:'third'};
    await source.setPending('cap-2',r2,300);await source.setPending('cap-3',r3,301);
    const capacity=await Promise.allSettled([
      source.approvePending('cap-2',{registration:r2,requestedAt:300},{id:'cap_pair_2',...r2,status:'active',created:302,lastActive:null,requests:0,failedSigs:0},1),
      source.approvePending('cap-3',{registration:r3,requestedAt:301},{id:'cap_pair_3',...r3,status:'active',created:303,lastActive:null,requests:0,failedSigs:0},1),
    ]);
    assert.equal(capacity.filter((result)=>result.status==='fulfilled').length,1,'serialized capacity must admit exactly one active approval');
    const rotationOld=(await source.list()).find((item)=>item.status==='active');assert.ok(rotationOld);
    const rotationNew:StoredPair={...rotationOld,id:'rotated_replacement',status:'active',created:400,lastActive:null,requests:0,failedSigs:0};
    assert.equal(await source.rotatePair(rotationOld,rotationNew),true);
    assert.equal(await source.rotatePair(rotationOld,{...rotationNew,id:'second_replacement'}),false,'stale rotation snapshot was accepted twice');
    while((await publisher.drainOnce()).attempted>0){}
    assert.equal((await source.get(rotationOld.id))?.status,'rotated');assert.equal((await source.get(rotationNew.id))?.status,'active');
    assert.equal((await pool.query('SELECT status FROM replica.bpc_pairs WHERE id=$1',[rotationOld.id])).rows[0].status,'rotated');
    assert.equal((await pool.query('SELECT status FROM replica.bpc_pairs WHERE id=$1',[rotationNew.id])).rows[0].status,'active');
    const rotationPolicy=successfulUsePolicy((await source.get(rotationNew.id))!);
    await source.atomicMutate(rotationNew.id,(current)=>({...current,scope:'read-write'}));
    assert.equal(await source.claimSuccessfulUse(rotationNew.id,450,rotationPolicy),'policy-changed','final claim authorized after current policy changed');
    assert.equal((await source.get(rotationNew.id))?.requests,0,'policy-change denial consumed a successful use');
    await source.atomicMutate(rotationNew.id,(current)=>({...current,expiresAt:500}));
    const expiryPolicy=successfulUsePolicy((await source.get(rotationNew.id))!);
    assert.equal(await source.claimSuccessfulUse(rotationNew.id,501,expiryPolicy),'time-expired','final claim authorized after current expiry');
    assert.deepEqual(await source.get(rotationNew.id),{...rotationNew,scope:'read-write',expiresAt:500,status:'expired'});
  });

  await check('(atomic registry) receiver approval conflict rolls back pending deletion and checkpoint', async () => {
    const sid='bpc:pair:receiver-conflict/v1';await provision(sid);await pool.query('CREATE SCHEMA replica');await applyDDLInSchema('replica');const replicaReady=await provisionSchemaVersion(serial,'replica');await provisionInSchema('replica',sid);
    const keyring={activeKeyId:'pair-key-1',resolveKey:()=>Buffer.alloc(32,10)};
    const source=new PgTransactionalPairStore(serial,READY,{streamId:sid,fenceToken:0n,keyring,maxPendingRows:10});
    const receiver=new PgReceiverCheckpoint<BpcPairMutation>(serial,sid,bpcPairMutationSanitizer,new PgPairMutationApplier(sid,keyring),replicaReady);
    const transport:OutboxTransport={async deliverAndAwaitAck(record){const d=await receiver.verifyAndApplyDelivered(record as OutboxRecord<BpcPairMutation>);return receiptFor(record,d);}};
    const publisher=new PgDurablePublisher<BpcPairMutation>(serial,sid,transport,'fail-authoritative-mutation',bpcPairMutationSanitizer,verifier,READY,{leaseMs:30_000});
    const jwk={kty:'EC',crv:'P-256',x:'x'.repeat(42)+'w',y:'y'.repeat(42)+'w'} as JsonWebKey;
    const reg={name:'conflict',scope:'read' as const,mode:'production' as const,secretHash:'s'.repeat(43),pubJwk:jwk,kind:'legitimate' as const};
    await source.setPending('conflict-token',reg,10);assert.equal((await publisher.drainOnce()).acked,1);
    const target:StoredPair={id:'conflict-pair',...reg,status:'active',created:11,lastActive:null,requests:0,failedSigs:0};
    await source.approvePending('conflict-token',{registration:reg,requestedAt:10},target,10);
    await pool.query(`INSERT INTO replica.bpc_pairs(id,name,scope,mode,secret_hash,pub_jwk,status,created,last_active,requests,failed_sigs,kind) VALUES($1,'planted','read','production',$2,$3,'active',1,NULL,0,0,'legitimate')`,[target.id,'s'.repeat(43),jwk]);
    await assert.rejects(()=>publisher.drainOnce(),/identity already exists/);
    assert.equal(Number((await pool.query("SELECT count(*)::int n FROM replica.bpc_pending WHERE token='conflict-token'")).rows[0].n),1,'receiver deleted pending before failed pair insert');
    assert.equal((await pool.query('SELECT name FROM replica.bpc_pairs WHERE id=$1',[target.id])).rows[0].name,'planted','receiver overwrote conflicting authority');
    assert.equal(Number((await pool.query('SELECT sequence FROM replica.ha_outbox_receiver_checkpoint WHERE stream_id=$1',[sid])).rows[0].sequence),1,'receiver checkpoint advanced across failed compound apply');
    assert.equal(Number((await pool.query('SELECT count(*)::int n FROM ha_outbox_rows WHERE stream_id=$1 AND acked_at IS NULL',[sid])).rows[0].n),1,'source lost retryable approval row');
  });

  await check('(pair authority) backpressure and stale fencing roll back the authoritative mutation', async () => {
    const sid = 'bpc:pair:rollback/v1'; await provision(sid);
    const keyring = { activeKeyId:'pair-key-1', resolveKey:() => Buffer.alloc(32, 7) };
    const limited = new PgTransactionalPairStore(serial, READY, { streamId: sid, fenceToken: 0n, keyring, maxPendingRows: 1 });
    const base: StoredPair = { id: 'rollback_pair', name: 'before', scope: 'read', mode: 'production', secretHash: 's'.repeat(43), pubJwk: { kty: 'EC', crv: 'P-256', x: 'x'.repeat(42)+'w', y: 'y'.repeat(42)+'w' }, status: 'active', created: 1, lastActive: null, requests: 0, failedSigs: 0, kind: 'legitimate' };
    await limited.set(base);
    await assert.rejects(() => limited.set({ ...base, name: 'must-rollback' }), /backpressure/i);
    assert.equal((await limited.get(base.id))?.name, 'before');
    assert.equal(Number((await pool.query('SELECT count(*)::int n FROM ha_outbox_rows WHERE stream_id=$1', [sid])).rows[0].n), 1);

    await pool.query('UPDATE ha_outbox_fence SET fence_token=2 WHERE stream_id=$1', [sid]);
    await assert.rejects(() => limited.delete(base.id), /fence token.*stale|stale.*fence/i);
    assert.equal((await limited.get(base.id))?.name, 'before', 'stale writer deleted authority despite rejected outbox append');

    const approvalSid='bpc:pair:approval-rollback/v1';await provision(approvalSid);
    const approvalStore=new PgTransactionalPairStore(serial,READY,{streamId:approvalSid,fenceToken:0n,keyring,maxPendingRows:2});
    const reg={name:'pending-safe',scope:'read' as const,mode:'production' as const,secretHash:'s'.repeat(43),pubJwk:base.pubJwk,kind:'legitimate' as const};
    await approvalStore.setPending('pending-safe',reg,10);
    await approvalStore.set({...base,id:'capacity-filler'});
    const approved:StoredPair={id:'must-not-exist',...reg,status:'active',created:11,lastActive:null,requests:0,failedSigs:0};
    await assert.rejects(()=>approvalStore.approvePending('pending-safe',{registration:reg,requestedAt:10},approved,10),/backpressure/i);
    assert.ok(await approvalStore.getPending('pending-safe'),'failed approval lost pending authority');
    assert.equal(await approvalStore.get(approved.id),undefined,'failed approval created a pair without its outbox mutation');
  });

  await check('(pair authority) governed schema precedes pg_temp and successful transactions discard session state', async () => {
    const sid='bpc:pair:temp-shadow/v1';await provision(sid);
    const tempPool=new Pool({connectionString,max:1});
    try{
      const tempDb=new NodePostgresTransactor(tempPool);
      const tempReady=await assertSchemaReady(tempDb,SCHEMA);
      const client=await tempPool.connect();
      try{await client.query('CREATE TEMP TABLE bpc_pairs (LIKE public.bpc_pairs INCLUDING ALL)');}finally{client.release();}
      const keyring={activeKeyId:'pair-key-1',resolveKey:()=>Buffer.alloc(32,7)};
      const store=new PgTransactionalPairStore(tempDb,tempReady,{streamId:sid,fenceToken:0n,keyring,maxPendingRows:10});
      const value:StoredPair={id:'temp_shadow_guard',name:'Public authority',scope:'read',mode:'production',secretHash:'s'.repeat(43),pubJwk:{kty:'EC',crv:'P-256',x:'x'.repeat(42)+'w',y:'y'.repeat(42)+'w'},status:'active',created:1,lastActive:null,requests:0,failedSigs:0,kind:'legitimate'};
      await store.set(value);
      assert.equal(Number((await pool.query("SELECT count(*)::int n FROM public.bpc_pairs WHERE id='temp_shadow_guard'")).rows[0].n),1,'pg_temp shadow captured authority mutation');
      assert.equal(Number((await pool.query('SELECT count(*)::int n FROM ha_outbox_rows WHERE stream_id=$1',[sid])).rows[0].n),1);
      assert.equal((await tempPool.query("SELECT to_regclass('pg_temp.bpc_pairs') AS r")).rows[0].r,null,'successful transaction returned pooled session with temp state');
    }finally{await tempPool.end();}
  });

  await check('(pair authority) encrypted payload cannot be transplanted across streams under the same seal key', async () => {
    const sourceSid='bpc:pair:tenant-a/v1', targetSid='bpc:pair:tenant-b/v1'; await provision(sourceSid); await provision(targetSid);
    await pool.query('CREATE SCHEMA replica'); await applyDDLInSchema('replica');
    const replicaReady=await provisionSchemaVersion(serial,'replica'); await provisionInSchema('replica',targetSid);
    const keyring={activeKeyId:'pair-key-1',resolveKey:()=>Buffer.alloc(32,7)};
    const source=new PgTransactionalPairStore(serial,READY,{streamId:sourceSid,fenceToken:0n,keyring,maxPendingRows:10});
    const p:StoredPair={id:'tenant_bound',name:'Tenant bound',scope:'read',mode:'production',secretHash:'s'.repeat(43),pubJwk:{kty:'EC',crv:'P-256',x:'x'.repeat(42)+'w',y:'y'.repeat(42)+'w'},status:'active',created:1,lastActive:null,requests:0,failedSigs:0,kind:'legitimate'};
    await source.set(p);
    const row=(await pool.query('SELECT mutation FROM ha_outbox_rows WHERE stream_id=$1 AND sequence=1',[sourceSid])).rows[0];
    const mutation=row.mutation as SanitizedMutation<BpcPairMutation>;
    const transplanted:OutboxRecord<BpcPairMutation>={contractVersion:'1',streamId:targetSid,sourceEpoch:'e1',sequence:1,fenceToken:'0',opDigest:canonicalOpDigest({streamId:targetSid,sourceEpoch:'e1',sequence:1,fenceToken:'0',mutation}),mutation};
    const receiver=new PgReceiverCheckpoint<BpcPairMutation>(serial,targetSid,bpcPairMutationSanitizer,new PgPairMutationApplier(targetSid,keyring),replicaReady);
    await assert.rejects(()=>receiver.verifyAndApplyDelivered(transplanted),/authentication failed/);
    assert.equal(Number((await pool.query("SELECT count(*)::int n FROM replica.bpc_pairs WHERE id='tenant_bound'")).rows[0].n),0);
  });

  await check('(pair authority) receiver authentication failure rolls back apply/history/checkpoint and leaves source retryable', async () => {
    const sid = 'bpc:pair:keyfail/v1'; await provision(sid);
    await pool.query('CREATE SCHEMA replica'); await applyDDLInSchema('replica');
    const replicaReady = await provisionSchemaVersion(serial, 'replica'); await provisionInSchema('replica', sid);
    const sourceKeyring = { activeKeyId:'pair-key-1', resolveKey:() => Buffer.alloc(32, 7) };
    const wrongKeyring = { activeKeyId:'pair-key-1', resolveKey:() => Buffer.alloc(32, 8) };
    const source = new PgTransactionalPairStore(serial, READY, { streamId: sid, fenceToken: 0n, keyring: sourceKeyring, maxPendingRows: 10 });
    const receiver = new PgReceiverCheckpoint<BpcPairMutation>(serial, sid, bpcPairMutationSanitizer, new PgPairMutationApplier(sid, wrongKeyring), replicaReady);
    const transport: OutboxTransport = { async deliverAndAwaitAck(record) { const d=await receiver.verifyAndApplyDelivered(record as OutboxRecord<BpcPairMutation>); return receiptFor(record,d); } };
    const publisher = new PgDurablePublisher<BpcPairMutation>(serial,sid,transport,'fail-authoritative-mutation',bpcPairMutationSanitizer,verifier,READY,{leaseMs:30_000});
    const p: StoredPair = { id:'keyfail',name:'Key fail',scope:'read',mode:'production',secretHash:'s'.repeat(43),pubJwk:{kty:'EC',crv:'P-256',x:'x'.repeat(42)+'w',y:'y'.repeat(42)+'w'},status:'active',created:1,lastActive:null,requests:0,failedSigs:0,kind:'legitimate' };
    await source.set(p);
    await assert.rejects(() => publisher.drainOnce(), /authentication failed/);
    assert.equal(Number((await pool.query("SELECT count(*)::int n FROM replica.bpc_pairs WHERE id='keyfail'")).rows[0].n),0);
    assert.equal(Number((await pool.query('SELECT sequence FROM replica.ha_outbox_receiver_checkpoint WHERE stream_id=$1',[sid])).rows[0].sequence),0);
    assert.equal(Number((await pool.query('SELECT count(*)::int n FROM replica.ha_outbox_applied WHERE stream_id=$1',[sid])).rows[0].n),0);
    assert.equal(await unacked(sid),1);
  });

  await check('(pair authority) combined readiness attests pair tables and database constraints reject private JWK material', async () => {
    await assertSchemaReady(serial, SCHEMA);
    await pool.query('DROP INDEX bpc_pending_requested_at');
    await assert.rejects(() => assertSchemaReady(serial, SCHEMA), /attestation failed/);
    await resetSchema();
    await assert.rejects(
      () => pool.query(`INSERT INTO bpc_pairs(id,name,scope,mode,secret_hash,pub_jwk,status,created,last_active,requests,failed_sigs,kind)
        VALUES('private_jwk','x','read','production',$1,$2,'active',1,NULL,0,0,'legitimate')`, ['s'.repeat(43), { kty:'EC',crv:'P-256',x:'x'.repeat(42)+'w',y:'y'.repeat(42)+'w',d:'private' }]),
      /check constraint/i,
    );
    for (const [token,registration] of [
      ['missing_jwk_fields',{name:'x',scope:'read',mode:'production',secretHash:'s'.repeat(43),pubJwk:{}}],
      ['null_jwk_fields',{name:'x',scope:'read',mode:'production',secretHash:'s'.repeat(43),pubJwk:{kty:'EC',crv:'P-256',x:null,y:null}}],
      ['private_pending',{name:'x',scope:'read',mode:'production',secretHash:'s'.repeat(43),pubJwk:{kty:'EC',crv:'P-256',x:'x'.repeat(42)+'w',y:'y'.repeat(42)+'w',d:'private'}}],
    ] as const) await assert.rejects(()=>pool.query('INSERT INTO bpc_pending(token,registration,requested_at) VALUES($1,$2,1)',[token,registration]),/check constraint/i);
    await assert.rejects(()=>pool.query('INSERT INTO bpc_pending(token,registration,requested_at) VALUES($1,$2,$3)',['unsafe_time',{name:'x',scope:'read',mode:'production',secretHash:'s'.repeat(43),pubJwk:{kty:'EC',crv:'P-256',x:'x'.repeat(42)+'w',y:'y'.repeat(42)+'w'}},'9007199254740992']),/check constraint/i);
    await assert.rejects(()=>pool.query(`INSERT INTO bpc_pairs(id,name,scope,mode,secret_hash,pub_jwk,status,created,last_active,requests,failed_sigs,cumulative_failures,kind)
      VALUES('unsafe_pair','x','read','production',$1,$2,'active',$3,NULL,0,0,0,'legitimate')`,['s'.repeat(43),{kty:'EC',crv:'P-256',x:'x'.repeat(42)+'w',y:'y'.repeat(42)+'w'},'9007199254740992']),/check constraint/i);
    for(const bad of ['NaN','Infinity']) await assert.rejects(()=>pool.query(`INSERT INTO bpc_pairs(id,name,scope,mode,secret_hash,pub_jwk,status,created,last_active,requests,failed_sigs,cumulative_failures,kind)
      VALUES($1,'x','read','production',$2,$3,'active',1,NULL,0,0,$4,'legitimate')`,[`bad_${bad}`, 's'.repeat(43),{kty:'EC',crv:'P-256',x:'x'.repeat(42)+'w',y:'y'.repeat(42)+'w'},bad]),/check constraint/i);
  });

  await check('(production adapter) deadline destroys a hung real-PG connection and pool recovers', async () => {
    const bounded = new NodePostgresTransactor(pool, {
      statementTimeoutMs: 30_000,
      transactionTimeoutMs: 150,
      rollbackTimeoutMs: 50,
    });
    const started = Date.now();
    await assert.rejects(
      () => bounded.transaction((exec) => exec.query('SELECT pg_sleep(30)')),
      /transaction deadline exceeded/,
    );
    assert.ok(Date.now() - started < 2_000, 'hung query was not bounded by the adapter deadline');
    const healthy = await pool.query('SELECT 1 AS ok');
    assert.equal(healthy.rows[0].ok, 1, 'pool did not recover after destroying the timed-out client');
    assert.equal(pool.waitingCount, 0, 'pool retained waiters after timed-out client destruction');
  });

  await check('(production adapter) callback transaction-control and multi-statement escapes roll back', async () => {
    await pool.query('DROP TABLE IF EXISTS tx_escape_guard');
    await pool.query('CREATE TABLE tx_escape_guard(id integer PRIMARY KEY)');
    for(const [i,sql] of ['COMMIT','/* sneaky */ COMMIT','ROLLBACK','SAVEPOINT x','SELECT 1; COMMIT'].entries()){
      await assert.rejects(()=>serial.transaction(async exec=>{
        await exec.query('INSERT INTO tx_escape_guard(id) VALUES($1)',[i]);
        await exec.query(sql);
        throw new Error('must not reach');
      }),/forbids|exactly one statement/);
    }
    assert.equal(Number((await pool.query('SELECT count(*)::int AS n FROM tx_escape_guard')).rows[0].n),0,'transaction-control escape committed data');
    await pool.query('DROP TABLE tx_escape_guard');
  });

  console.log(`\n# ${passed} checks passed`);
}

main().then(() => pool.end()).then(() => process.exit(0)).catch(async (e) => { console.error('FAILED:', e); await pool.end().catch(() => {}); process.exit(1); });
