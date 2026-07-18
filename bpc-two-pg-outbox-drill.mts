/**
 * Two-independent-PostgreSQL mechanism drill for BPC issue #16.
 *
 * This proves the existing pair/outbox/publisher/receiver path across distinct
 * PostgreSQL cluster identities and state authorities. Same-host CI containers
 * do not prove independent physical failure domains. The adapter below is
 * deliberately in-process and test-only: this is NOT authenticated-network,
 * promotion, failover, split-brain, availability, or HA evidence. Issue #16
 * remains open for those acceptance gates.
 */
import assert from 'node:assert/strict';
import pg from 'pg';

import {
  HA_OUTBOX_PG_SCHEMA,
  NodePostgresTransactor,
  PgDurablePublisher,
  PgPairMutationApplier,
  PgReceiverCheckpoint,
  PgTransactionalPairStore,
  assertSchemaReady,
  bpcPairMutationSanitizer,
  provisionSchemaVersion,
  type AckReceipt,
  type AckReceiptVerifier,
  type BpcPairMutation,
  type MutationApplier,
  type OutboxRecord,
  type OutboxTransport,
  type PgExecutor,
  type ReceiverDecision,
  type SchemaReadyToken,
  type StoredPair,
} from './packages/server/src/index.ts';

const sourceUrl = process.env['BPC_TEST_POSTGRES_URL'];
const receiverUrl = process.env['BPC_TEST_POSTGRES_B_URL'];
if (!sourceUrl || !receiverUrl) {
  throw new Error('BPC_TEST_POSTGRES_URL and BPC_TEST_POSTGRES_B_URL are required for the two-PG mechanism drill');
}
if (sourceUrl === receiverUrl) throw new Error('the two-PG mechanism drill requires distinct connection URLs');

const { Pool } = pg;
const sourcePool = new Pool({ connectionString: sourceUrl, max: 8 });
let receiverPool = new Pool({ connectionString: receiverUrl, max: 8 });
const streamId = 'bpc:pair:two-pg-drill/v1';
const epoch = 'e1';
const sealKey = Buffer.alloc(32, 17);
const keyring = {
  activeKeyId: 'pair-key-1',
  resolveKey(keyId: string): Buffer {
    if (keyId !== 'pair-key-1') throw new Error('unknown pair seal key');
    return sealKey;
  },
};

async function resetDatabase(pool: pg.Pool): Promise<void> {
  await pool.query(
    'DROP TABLE IF EXISTS bpc_2pg_effects, bpc_pending, bpc_pairs, ha_outbox_rows, ha_outbox_applied, ha_outbox_fence, ha_outbox_source_checkpoint, ha_outbox_receiver_checkpoint, ha_outbox_publisher_lease, ha_outbox_quarantine, ha_outbox_meta CASCADE',
  );
  for (const statement of HA_OUTBOX_PG_SCHEMA.split(';').map((part) => part.trim()).filter(Boolean)) {
    await pool.query(statement);
  }
}

async function provisionStream(pool: pg.Pool): Promise<void> {
  await pool.query('INSERT INTO ha_outbox_fence (stream_id, fence_token) VALUES ($1, 0)', [streamId]);
  await pool.query(
    'INSERT INTO ha_outbox_source_checkpoint (stream_id, source_epoch, sequence) VALUES ($1, $2, 0)',
    [streamId, epoch],
  );
  await pool.query(
    'INSERT INTO ha_outbox_receiver_checkpoint (stream_id, source_epoch, sequence) VALUES ($1, $2, 0)',
    [streamId, epoch],
  );
}

interface BacklogSnapshot {
  sourceSequence: number;
  receiverSequence: number;
  receiverLagRows: number;
  sourceUnackedRows: number;
  sourceAckedRows: number;
}

async function backlog(): Promise<BacklogSnapshot> {
  const source = await sourcePool.query(
    `SELECT c.sequence::int AS sequence,
            count(*) FILTER (WHERE r.acked_at IS NULL AND r.quarantined_at IS NULL)::int AS unacked,
            count(*) FILTER (WHERE r.acked_at IS NOT NULL)::int AS acked
       FROM ha_outbox_source_checkpoint c
       LEFT JOIN ha_outbox_rows r ON r.stream_id = c.stream_id
      WHERE c.stream_id = $1
      GROUP BY c.sequence`,
    [streamId],
  );
  const receiver = await receiverPool.query(
    'SELECT sequence::int AS sequence FROM ha_outbox_receiver_checkpoint WHERE stream_id = $1',
    [streamId],
  );
  const sourceSequence = Number(source.rows[0].sequence);
  const receiverSequence = Number(receiver.rows[0].sequence);
  return {
    sourceSequence,
    receiverSequence,
    receiverLagRows: sourceSequence - receiverSequence,
    sourceUnackedRows: Number(source.rows[0].unacked),
    sourceAckedRows: Number(source.rows[0].acked),
  };
}

const receiptSignature = (record: OutboxRecord<unknown>, decision: ReceiverDecision) =>
  `test-only:${record.streamId}:${record.sourceEpoch}:${record.sequence}:${record.opDigest}:${decision}`;
const receiptFor = (record: OutboxRecord<unknown>, decision: ReceiverDecision): AckReceipt => ({
  streamId: record.streamId,
  sourceEpoch: record.sourceEpoch,
  sequence: record.sequence,
  opDigest: record.opDigest,
  decision,
  receiverId: 'receiver-b-test-only',
  keyId: 'test-only-key',
  issuedAt: 'test-only',
  signature: receiptSignature(record, decision),
});
const verifier: AckReceiptVerifier = {
  async verify(receipt, record) {
    if (receipt.receiverId !== 'receiver-b-test-only' || receipt.keyId !== 'test-only-key') {
      throw new Error('test receipt authority mismatch');
    }
    if (receipt.signature !== receiptSignature(record, receipt.decision)) {
      throw new Error('test receipt binding mismatch');
    }
  },
};

function pair(index: number): StoredPair {
  return {
    id: `two_pg_pair_${index}`,
    name: `Two PG pair ${index}`,
    scope: 'read-write',
    mode: 'production',
    secretHash: 's'.repeat(43),
    pubJwk: { kty: 'EC', crv: 'P-256', x: `${'x'.repeat(42)}w`, y: `${'y'.repeat(42)}w` },
    status: 'active',
    created: 1_000 + index,
    lastActive: null,
    requests: index,
    failedSigs: 0,
    kind: 'legitimate',
  };
}

async function receiverComponents(pool: pg.Pool): Promise<{
  ready: SchemaReadyToken;
  receiver: PgReceiverCheckpoint<BpcPairMutation>;
}> {
  const db = new NodePostgresTransactor(pool, { maxSerializationRetries: 20 });
  const ready = await assertSchemaReady(db, 'public');
  const pairApplier = new PgPairMutationApplier(streamId, keyring);
  const countedApplier: MutationApplier<BpcPairMutation> = {
    async applyInTx(exec: PgExecutor, record: OutboxRecord<BpcPairMutation>): Promise<void> {
      await pairApplier.applyInTx(exec, record);
      await exec.query(
        `INSERT INTO bpc_2pg_effects (source_epoch, sequence, op_digest, apply_count)
         VALUES ($1, $2, $3, 1)
         ON CONFLICT (source_epoch, sequence)
         DO UPDATE SET apply_count = bpc_2pg_effects.apply_count + 1`,
        [record.sourceEpoch, record.sequence, record.opDigest],
      );
    },
  };
  return {
    ready,
    receiver: new PgReceiverCheckpoint(
      db,
      streamId,
      bpcPairMutationSanitizer,
      countedApplier,
      ready,
    ),
  };
}

function testOnlyTransport(
  receiver: PgReceiverCheckpoint<BpcPairMutation>,
  decisions: ReceiverDecision[],
  loseFirstAck: boolean,
): OutboxTransport {
  let shouldLoseAck = loseFirstAck;
  return {
    async deliverAndAwaitAck(record) {
      const decision = await receiver.verifyAndApplyDelivered(record as OutboxRecord<BpcPairMutation>);
      decisions.push(decision);
      if (shouldLoseAck) {
        shouldLoseAck = false;
        throw new Error('test-only injected ACK loss after receiver commit');
      }
      return receiptFor(record, decision);
    },
  };
}

async function main(): Promise<void> {
  const sourceIdentity = String((await sourcePool.query('SELECT system_identifier::text FROM pg_control_system()')).rows[0].system_identifier);
  const receiverIdentity = String((await receiverPool.query('SELECT system_identifier::text FROM pg_control_system()')).rows[0].system_identifier);
  assert.notEqual(sourceIdentity, receiverIdentity, 'source and receiver must be different PostgreSQL clusters');

  await resetDatabase(sourcePool);
  await resetDatabase(receiverPool);
  const sourceDb = new NodePostgresTransactor(sourcePool, { maxSerializationRetries: 20 });
  const sourceReady = await provisionSchemaVersion(sourceDb, 'public');
  const initialReceiverDb = new NodePostgresTransactor(receiverPool, { maxSerializationRetries: 20 });
  await provisionSchemaVersion(initialReceiverDb, 'public');
  await provisionStream(sourcePool);
  await provisionStream(receiverPool);
  await receiverPool.query(
    `CREATE TABLE bpc_2pg_effects (
       source_epoch text NOT NULL,
       sequence bigint NOT NULL,
       op_digest text NOT NULL,
       apply_count integer NOT NULL,
       PRIMARY KEY (source_epoch, sequence)
     )`,
  );

  const source = new PgTransactionalPairStore(sourceDb, sourceReady, {
    streamId,
    fenceToken: 0n,
    keyring,
    maxPendingRows: 100,
  });
  const decisions: ReceiverDecision[] = [];
  const initialReceiver = (await receiverComponents(receiverPool)).receiver;
  const lostAckPublisher = new PgDurablePublisher<BpcPairMutation>(
    sourceDb,
    streamId,
    testOnlyTransport(initialReceiver, decisions, true),
    'fail-authoritative-mutation',
    bpcPairMutationSanitizer,
    verifier,
    sourceReady,
    { leaseMs: 5_000 },
  );

  await source.set(pair(1));
  await assert.rejects(() => lostAckPublisher.drainOnce(), /injected ACK loss/);
  assert.deepEqual(decisions, ['applied']);
  assert.deepEqual(await backlog(), {
    sourceSequence: 1,
    receiverSequence: 1,
    receiverLagRows: 0,
    sourceUnackedRows: 1,
    sourceAckedRows: 0,
  });

  await receiverPool.end();
  for (let index = 2; index <= 4; index++) await source.set(pair(index));
  await assert.rejects(() => lostAckPublisher.drainOnce(), /pool.*ended|Cannot use a pool after calling end/i);

  receiverPool = new Pool({ connectionString: receiverUrl, max: 8 });
  assert.equal(
    String((await receiverPool.query('SELECT system_identifier::text FROM pg_control_system()')).rows[0].system_identifier),
    receiverIdentity,
    'receiver restart must reopen the same durable PostgreSQL cluster',
  );
  assert.deepEqual(await backlog(), {
    sourceSequence: 4,
    receiverSequence: 1,
    receiverLagRows: 3,
    sourceUnackedRows: 4,
    sourceAckedRows: 0,
  });

  const restartedReceiver = (await receiverComponents(receiverPool)).receiver;
  const convergingPublisher = new PgDurablePublisher<BpcPairMutation>(
    sourceDb,
    streamId,
    testOnlyTransport(restartedReceiver, decisions, false),
    'fail-authoritative-mutation',
    bpcPairMutationSanitizer,
    verifier,
    sourceReady,
    { leaseMs: 5_000 },
  );
  const convergenceStartedAt = Date.now();
  for (let round = 0; round < 8 && (await backlog()).sourceUnackedRows > 0; round++) {
    await convergingPublisher.drainOnce();
  }
  const convergenceMs = Date.now() - convergenceStartedAt;

  assert.deepEqual(decisions, ['applied', 'duplicate-ok', 'applied', 'applied', 'applied']);
  assert.deepEqual(await backlog(), {
    sourceSequence: 4,
    receiverSequence: 4,
    receiverLagRows: 0,
    sourceUnackedRows: 0,
    sourceAckedRows: 4,
  });
  const effects = await receiverPool.query(
    'SELECT sequence::int AS sequence, apply_count::int AS apply_count FROM bpc_2pg_effects ORDER BY sequence',
  );
  assert.deepEqual(effects.rows, [1, 2, 3, 4].map((sequence) => ({ sequence, apply_count: 1 })));
  assert.equal(
    Number((await receiverPool.query('SELECT count(*)::int AS count FROM ha_outbox_applied WHERE stream_id = $1', [streamId])).rows[0].count),
    4,
    'receiver durable applied history must contain each operation exactly once',
  );
  const sourcePairs = await sourcePool.query('SELECT * FROM bpc_pairs ORDER BY id');
  const receiverPairs = await receiverPool.query('SELECT * FROM bpc_pairs ORDER BY id');
  assert.deepEqual(receiverPairs.rows, sourcePairs.rows, 'acknowledged source pair state must converge exactly');

  console.log('# BPC two-independent-PG mechanism drill');
  console.log(`  source system_identifier: ${sourceIdentity}`);
  console.log(`  receiver system_identifier: ${receiverIdentity}`);
  console.log('  peak receiver lag rows: 3');
  console.log('  peak source unacked rows: 4 (includes one applied-but-ACK-lost row)');
  console.log(`  convergence after receiver reopen: ${convergenceMs}ms`);
  console.log('  post-convergence missing acknowledged rows: 0');
  console.log('  boundary: test-only in-process adapter; no network/HA/promotion claim; #16 remains open');
}

try {
  await main();
} finally {
  await sourcePool.end().catch(() => {});
  await receiverPool.end().catch(() => {});
  sealKey.fill(0);
}
