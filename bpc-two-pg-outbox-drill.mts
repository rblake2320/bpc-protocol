/**
 * Two-independent-PostgreSQL mechanism drill for BPC issue #16.
 *
 * This proves the existing pair/outbox/publisher/receiver path across distinct
 * PostgreSQL cluster identities and state authorities. Same-host CI containers
 * do not prove independent physical failure domains. The loopback HTTP hop is
 * authenticated and replay-resistant, but same-host CI is NOT
 * independent-network, promotion, failover, split-brain, availability, or HA
 * evidence. Issue #16 remains open for those acceptance gates.
 */
import assert from 'node:assert/strict';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { createServer, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import pg from 'pg';

import {
  HA_OUTBOX_PG_SCHEMA,
  BPC_TRANSPORT_NONCE_SCHEMA,
  HttpOutboxTransport,
  NodePostgresTransactor,
  PgDurablePublisher,
  PgPairMutationApplier,
  PgReceiverCheckpoint,
  PgReplayNonceStore,
  PgTransactionalPairStore,
  assertSchemaReady,
  bpcPairMutationSanitizer,
  createHttpOutboxReceiver,
  provisionSchemaVersion,
  type AckReceipt,
  type AckReceiptVerifier,
  type BpcPairMutation,
  type MutationApplier,
  type OutboxRecord,
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
let drillServer: import('node:http').Server | null = null;
const streamId = 'bpc:pair:two-pg-drill/v1';
const epoch = 'e1';
const sealKey = Buffer.alloc(32, 17);
const receiptKey = Buffer.alloc(32, 19);
const keyring = {
  activeKeyId: 'pair-key-1',
  resolveKey(keyId: string): Buffer {
    if (keyId !== 'pair-key-1') throw new Error('unknown pair seal key');
    return sealKey;
  },
};

async function resetDatabase(pool: pg.Pool): Promise<void> {
  await pool.query(
    'DROP TABLE IF EXISTS bpc_transport_nonce, bpc_2pg_effects, bpc_pending, bpc_pairs, ha_outbox_rows, ha_outbox_applied, ha_outbox_fence, ha_outbox_source_checkpoint, ha_outbox_receiver_checkpoint, ha_outbox_publisher_lease, ha_outbox_quarantine, ha_outbox_meta CASCADE',
  );
  for (const statement of HA_OUTBOX_PG_SCHEMA.split(';').map((part) => part.trim()).filter(Boolean)) {
    await pool.query(statement);
  }
  for (const statement of BPC_TRANSPORT_NONCE_SCHEMA.split(';').map((part) => part.trim()).filter(Boolean)) {
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

const receiptSignature = (receipt: Omit<AckReceipt, 'signature'>) =>
  createHmac('sha256', receiptKey)
    .update([
      receipt.receiverId, receipt.keyId, receipt.streamId, receipt.sourceEpoch,
      receipt.sequence, receipt.opDigest, receipt.decision, receipt.issuedAt,
    ].join('|'))
    .digest('base64url');
const receiptFor = (record: OutboxRecord<unknown>, decision: ReceiverDecision): AckReceipt => {
  const value: Omit<AckReceipt, 'signature'> = {
    streamId: record.streamId,
    sourceEpoch: record.sourceEpoch,
    sequence: record.sequence,
    opDigest: record.opDigest,
    decision,
    receiverId: 'receiver-b-drill',
    keyId: 'receiver-receipt-v1',
    issuedAt: String(Date.now()),
  };
  return { ...value, signature: receiptSignature(value) };
};
const verifier: AckReceiptVerifier = {
  async verify(receipt, record) {
    if (receipt.receiverId !== 'receiver-b-drill' || receipt.keyId !== 'receiver-receipt-v1') {
      throw new Error('test receipt authority mismatch');
    }
    const actual = Buffer.from(receipt.signature, 'base64url');
    const expected = Buffer.from(receiptSignature(receipt), 'base64url');
    if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
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
  let activeReceiver = (await receiverComponents(receiverPool)).receiver;
  const requestSecret = Buffer.alloc(32, 31);
  const responseSecret = Buffer.alloc(32, 37);
  let loseNextAck = true;
  const openNonceStore = () => PgReplayNonceStore.open(
      new NodePostgresTransactor({
        async connect() {
          return receiverPool.connect();
        },
      }),
      'public',
    );
  const makeReceiverHandler = async () => createHttpOutboxReceiver({
      expectedPath: '/bpc/outbox',
      resolveRequestKey: (keyId) => keyId === 'source-a-v1' ? requestSecret : null,
      responseKeyId: 'receiver-b-v1',
      responseSecret,
      nonceStore: await openNonceStore(),
      receive: async (record) => {
        const decision = await activeReceiver.verifyAndApplyDelivered(
          record as OutboxRecord<BpcPairMutation>,
        );
        decisions.push(decision);
        return receiptFor(record, decision);
      },
    });
  let receiverHandler = await makeReceiverHandler();
  const server = createServer((req, res) => {
    if (loseNextAck) {
      const originalEnd = res.end.bind(res);
      res.end = ((...args: Parameters<ServerResponse['end']>) => {
        if (res.statusCode === 200) {
          loseNextAck = false;
          res.socket?.destroy(new Error('drill ACK loss after receiver commit'));
          return res;
        }
        return originalEnd(...args);
      }) as ServerResponse['end'];
    }
    receiverHandler(req, res);
  });
  drillServer = server;
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const transport = new HttpOutboxTransport({
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/bpc/outbox`,
    fetch: fetch as never,
    requestKeyId: 'source-a-v1',
    requestSecret,
    resolveResponseKey: (keyId) => keyId === 'receiver-b-v1' ? responseSecret : null,
    ackVerifier: verifier,
  });
  const lostAckPublisher = new PgDurablePublisher<BpcPairMutation>(
    sourceDb,
    streamId,
    transport,
    'fail-authoritative-mutation',
    bpcPairMutationSanitizer,
    verifier,
    sourceReady,
    { leaseMs: 5_000 },
  );

  await source.set(pair(1));
  await assert.rejects(() => lostAckPublisher.drainOnce(), /transport request failed/);
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
  await assert.rejects(() => lostAckPublisher.drainOnce(), /HTTP 500/);

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

  activeReceiver = (await receiverComponents(receiverPool)).receiver;
  const convergingPublisher = new PgDurablePublisher<BpcPairMutation>(
    sourceDb,
    streamId,
    transport,
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

  const firstRow = (await sourcePool.query(
    `SELECT source_epoch, sequence::int AS sequence, fence_token::text, op_digest, mutation
       FROM ha_outbox_rows WHERE stream_id=$1 AND sequence=1`,
    [streamId],
  )).rows[0];
  const replayRecord: OutboxRecord<BpcPairMutation> = {
    contractVersion: '1', streamId, sourceEpoch: String(firstRow.source_epoch),
    sequence: Number(firstRow.sequence), fenceToken: String(firstRow.fence_token),
    opDigest: String(firstRow.op_digest), mutation: firstRow.mutation as BpcPairMutation,
  };
  const replayTransport = new HttpOutboxTransport({
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/bpc/outbox`,
    fetch: fetch as never,
    requestKeyId: 'source-a-v1', requestSecret,
    resolveResponseKey: (keyId) => keyId === 'receiver-b-v1' ? responseSecret : null,
    ackVerifier: verifier,
    nonce: () => 'durable-replay-nonce-abcdefghijklmnop',
  });
  assert.equal((await replayTransport.deliverAndAwaitAck(replayRecord)).decision, 'duplicate-ok');
  receiverHandler = await makeReceiverHandler();
  await assert.rejects(
    () => replayTransport.deliverAndAwaitAck(replayRecord),
    (error: unknown) => error instanceof Error && /HTTP 401/.test(error.message),
  );
  assert.equal(
    Number((await receiverPool.query('SELECT apply_count FROM bpc_2pg_effects WHERE source_epoch=$1 AND sequence=1', [epoch])).rows[0].apply_count),
    1,
    'durable request replay after nonce-store reconstruction must not reapply the mutation',
  );

  const ddlBlocker = await receiverPool.connect();
  await ddlBlocker.query('BEGIN');
  await ddlBlocker.query('LOCK TABLE bpc_transport_nonce IN ACCESS EXCLUSIVE MODE');
  const lockProofTransport = new HttpOutboxTransport({
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/bpc/outbox`,
    fetch: fetch as never,
    requestKeyId: 'source-a-v1', requestSecret,
    resolveResponseKey: (keyId) => keyId === 'receiver-b-v1' ? responseSecret : null,
    ackVerifier: verifier,
  });
  let lockProofSettled = false;
  const lockProof = lockProofTransport.deliverAndAwaitAck(replayRecord).finally(() => {
    lockProofSettled = true;
  });
  await new Promise((resolve) => setTimeout(resolve, 100));
  assert.equal(lockProofSettled, false, 'nonce admission must wait behind a conflicting DDL lock');
  await ddlBlocker.query('COMMIT');
  ddlBlocker.release();
  assert.equal((await lockProof).decision, 'duplicate-ok');

  await receiverPool.query('DROP INDEX bpc_transport_nonce_expiry');
  await receiverPool.query(
    'CREATE INDEX bpc_transport_nonce_wrong ON bpc_transport_nonce (nonce)',
  );
  const driftTransport = new HttpOutboxTransport({
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/bpc/outbox`,
    fetch: fetch as never,
    requestKeyId: 'source-a-v1', requestSecret,
    resolveResponseKey: (keyId) => keyId === 'receiver-b-v1' ? responseSecret : null,
    ackVerifier: verifier,
  });
  await assert.rejects(
    () => driftTransport.deliverAndAwaitAck(replayRecord),
    (error: unknown) => error instanceof Error && /HTTP 500/.test(error.message),
  );
  await receiverPool.query('DROP INDEX bpc_transport_nonce_wrong');
  await receiverPool.query(
    'CREATE INDEX bpc_transport_nonce_expiry ON bpc_transport_nonce (expires_at)',
  );
  await source.set(pair(5));
  const terminalAuthTransport = new HttpOutboxTransport({
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/bpc/outbox`,
    fetch: fetch as never,
    requestKeyId: 'source-a-v1', requestSecret: Buffer.alloc(32, 99),
    resolveResponseKey: (keyId) => keyId === 'receiver-b-v1' ? responseSecret : null,
    ackVerifier: verifier,
  });
  const terminalPublisher = new PgDurablePublisher<BpcPairMutation>(
    sourceDb, streamId, terminalAuthTransport, 'fail-authoritative-mutation',
    bpcPairMutationSanitizer, verifier, sourceReady, { leaseMs: 5_000 },
  );
  assert.deepEqual(await terminalPublisher.drainOnce(), {
    published: 0, acked: 0, quarantined: 1, retriable: false,
  });
  assert.equal(
    String((await sourcePool.query(
      'SELECT decision FROM ha_outbox_quarantine WHERE stream_id=$1 AND sequence=5',
      [streamId],
    )).rows[0].decision),
    'reject-transport-terminal',
  );
  await source.set(pair(6));
  const restartedPublisher = new PgDurablePublisher<BpcPairMutation>(
    sourceDb, streamId, transport, 'fail-authoritative-mutation',
    bpcPairMutationSanitizer, verifier, sourceReady, { leaseMs: 5_000 },
  );
  assert.deepEqual(await restartedPublisher.drainOnce(), {
    published: 0, acked: 0, quarantined: 0, retriable: false,
  });
  const haltedRows = (await sourcePool.query(
    'SELECT sequence::int AS sequence, acked_at, quarantined_at FROM ha_outbox_rows WHERE stream_id=$1 AND sequence IN (5,6) ORDER BY sequence',
    [streamId],
  )).rows;
  assert.deepEqual(haltedRows.map((row) => row.sequence), [5, 6]);
  assert.equal(haltedRows[0].acked_at, null);
  assert.ok(haltedRows[0].quarantined_at instanceof Date);
  assert.equal(haltedRows[1].acked_at, null);
  assert.equal(haltedRows[1].quarantined_at, null,
    'a terminal quarantine must remain an ordered-stream barrier after publisher restart');
  assert.equal(
    Number((await receiverPool.query(
      'SELECT sequence FROM ha_outbox_receiver_checkpoint WHERE stream_id=$1 AND source_epoch=$2',
      [streamId, epoch],
    )).rows[0].sequence),
    4,
    'the row after a terminal quarantine must not reach the receiver',
  );

  console.log('# BPC two-independent-PG mechanism drill');
  console.log(`  source system_identifier: ${sourceIdentity}`);
  console.log(`  receiver system_identifier: ${receiverIdentity}`);
  console.log('  peak receiver lag rows: 3');
  console.log('  peak source unacked rows: 4 (includes one applied-but-ACK-lost row)');
  console.log(`  convergence after receiver reopen: ${convergenceMs}ms`);
  console.log('  post-convergence missing acknowledged rows: 0');
  console.log('  authenticated HTTP hop: HMAC request + durable nonce + attempt-bound response + signed receipt');
  console.log('  authenticated raw-request replay after nonce-store reconstruction: rejected');
  console.log('  replay-authority DDL lock + exact-index drift: enforced before semantic apply');
  console.log('  terminal authentication failure: durably quarantined and halts later ordered delivery');
  console.log('  post-recovery missing committed rows: 0 (recoverable receiver reconnect)');
  console.log('  boundary: same-host loopback network; no HA/promotion/split-brain claim; #16 remains open');

  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  drillServer = null;
  requestSecret.fill(0);
  responseSecret.fill(0);
}

try {
  await main();
} finally {
  if (drillServer) await new Promise<void>((resolve) => drillServer!.close(() => resolve()));
  await sourcePool.end().catch(() => {});
  await receiverPool.end().catch(() => {});
  sealKey.fill(0);
}
