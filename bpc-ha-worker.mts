import { createHmac, createPrivateKey, createPublicKey, timingSafeEqual } from 'node:crypto';
import pg from 'pg';
import Redis from 'ioredis';

import {
  HttpOutboxTransport,
  BpcRedisQuorumFenceStore,
  PgRedisFenceWitness,
  NodePostgresTransactor,
  PgDurablePublisher,
  PgSourceLeaseFence,
  createHaPairAuthority,
  assertSchemaReady,
  provisionBpcHaSchema,
  signNodeIdentityChallenge,
  bpcPairMutationSanitizer,
  type AckReceipt,
  type AckReceiptVerifier,
  type OutboxRecord,
  type SourceLeaseBinding,
} from './packages/server/dist/index.js';

const required = (name: string): string => {
  const value = process.env[name]; if (!value) throw new Error(`${name} required`); return value;
};
const mode = required('BPC_HA_WORKER_MODE');
const { Pool } = pg;
const pool = new Pool({ connectionString: required('BPC_HA_PG_URL'), max: 3 });
pool.on('error', () => {});
const db = new NodePostgresTransactor(pool as never,{transactionTimeoutMs:Number(process.env['BPC_HA_TRANSACTION_TIMEOUT_MS']??35_000)});

const ackBody = (a: Omit<AckReceipt, 'signature'>) => [a.receiverId,a.keyId,a.streamId,a.sourceEpoch,a.sequence,a.opDigest,a.decision,a.issuedAt].join('|');

try {
  const ready = await assertSchemaReady(db, 'public');
  const haReady=await provisionBpcHaSchema(db);
  if (mode === 'publisher') {
    const secret = Buffer.from(required('BPC_HA_REQUEST_SECRET'), 'base64url');
    const responseSecret = Buffer.from(required('BPC_HA_RESPONSE_SECRET'), 'base64url');
    const ackSecret = Buffer.from(required('BPC_HA_ACK_SECRET'), 'base64url');
    const ackVerifier: AckReceiptVerifier = { async verify(receipt, record: OutboxRecord<unknown>) {
      if (receipt.receiverId !== 'receiver-b' || receipt.keyId !== 'ack-v1' || receipt.streamId !== record.streamId || receipt.sourceEpoch !== record.sourceEpoch || receipt.sequence !== record.sequence || receipt.opDigest !== record.opDigest) throw new Error('ack binding invalid');
      const got = Buffer.from(receipt.signature, 'base64url');
      const want = createHmac('sha256', ackSecret).update(ackBody(receipt)).digest();
      if (got.length !== want.length || !timingSafeEqual(got, want)) throw new Error('ack signature invalid');
    } };
    const transport = new HttpOutboxTransport({
      url: required('BPC_HA_RECEIVER_URL'), fetch: fetch as never,
      requestKeyId: 'request-v1', requestSecret: secret,
      resolveResponseKey: (keyId) => keyId === 'response-v1' ? responseSecret : null,
      ackVerifier, timeoutMs: 15_000,
    });
    const publisher = new PgDurablePublisher(db, required('BPC_HA_STREAM_ID'), transport,
      'fail-authoritative-mutation', bpcPairMutationSanitizer, ackVerifier, ready, { leaseMs: 2_000 });
    const result = await publisher.drainOnce();
    process.stdout.write(`${JSON.stringify({ ok: true, result })}\n`);
    secret.fill(0); responseSecret.fill(0); ackSecret.fill(0);
  } else if (mode === 'stale-writer') {
    let redisPartitionObserved = true;
    if (process.env['BPC_HA_REDIS_PROBE_URL']) {
      const redis = new Redis(process.env['BPC_HA_REDIS_PROBE_URL'], {
        lazyConnect: true, connectTimeout: 400, maxRetriesPerRequest: 0,
        retryStrategy: () => null,
      });
      redis.on('error', () => {});
      try { await redis.connect(); await redis.ping(); redisPartitionObserved = false; }
      catch { redisPartitionObserved = true; }
      finally { redis.disconnect(); }
    }
    const binding = JSON.parse(required('BPC_HA_LEASE_BINDING')) as SourceLeaseBinding;
    const publicKey = createPublicKey(required('BPC_HA_GUARD_PUBLIC_KEY'));
    const nodePublicKey=createPublicKey(required('BPC_HA_NODE_PUBLIC_KEY')),nodePrivateKey=createPrivateKey(required('BPC_HA_NODE_PRIVATE_KEY'));
    const sealKey = Buffer.from(required('BPC_HA_SEAL_KEY'), 'base64url');
    const mutationSecret=Buffer.from(required('BPC_HA_MUTATION_TICKET_SECRET'),'base64url');
    let denied = false;
    try {
      const redisClients=required('BPC_HA_REDIS_URLS').split(',').map(url=>{const r=new Redis(url,{connectTimeout:400,maxRetriesPerRequest:0,retryStrategy:()=>null});r.on('error',()=>{});return r;});
      const resolver={ resolve: (keyId:string) => keyId === 'guard-v1' ? publicKey:keyId===binding.nodeCredentialKeyId?nodePublicKey:null };
      const controlPool=new Pool({connectionString:required('BPC_HA_CONTROL_PG_URL'),max:1});controlPool.on('error',()=>{});const controlDb=new NodePostgresTransactor(controlPool as never);const controlReady=await provisionBpcHaSchema(controlDb);
      const quorum=await BpcRedisQuorumFenceStore.open(redisClients,resolver,await PgRedisFenceWitness.open(controlDb,controlReady,resolver),'bpc:ha:final');
      const mutationSigner={keyId:'mutation-v1',async sign(message:Uint8Array){return createHmac('sha256',mutationSecret).update(message).digest('hex');}};
      const fence = await PgSourceLeaseFence.open(db,haReady,resolver, binding,quorum,{keyId:binding.nodeCredentialKeyId,prove:async challenge=>signNodeIdentityChallenge(binding.nodeCredentialKeyId,nodePrivateKey,challenge)},mutationSigner);
      const store = createHaPairAuthority(db, ready, {
        streamId: required('BPC_HA_STREAM_ID'), fenceToken: BigInt(binding.epoch),
        keyring: { activeKeyId: 'seal-v1', resolveKey: () => sealKey }, maxPendingRows: 100,
      },fence);
      await store.set({ id:'stale-writer', name:'stale', scope:'read', mode:'production', secretHash:Buffer.alloc(32,9).toString('base64url'), pubJwk:{kty:'EC',crv:'P-256',x:Buffer.alloc(32,1).toString('base64url'),y:Buffer.alloc(32,2).toString('base64url')}, status:'active', created:Date.now(), lastActive:null, requests:0, failedSigs:0 });
    } catch (error) {
      denied = error instanceof Error && /lease expired|stale|revoked|fail closed|authority|witness|connection/i.test(error.message);
      if (!denied) throw error;
    }
    process.stdout.write(`${JSON.stringify({ ok: true, denied, redisPartitionObserved })}\n`);
    sealKey.fill(0);mutationSecret.fill(0);
  } else {
    throw new Error(`unknown worker mode ${mode}`);
  }
} finally {
  await pool.end().catch(() => {});
}
