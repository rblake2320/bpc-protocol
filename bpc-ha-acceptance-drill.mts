/**
 * Frozen BPC #16 acceptance: real A/B PostgreSQL authorities, real Redis
 * external fencing, authenticated network replication, actual publisher
 * SIGKILL/restart, expiring-lease old-writer refusal under a live Redis
 * partition, snapshot+tail resync, promotion, and measured per-fault RPO/RTO.
 */
import assert from 'node:assert/strict';
import { createHmac, generateKeyPairSync, timingSafeEqual } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import net from 'node:net';
import { spawn, type ChildProcess } from 'node:child_process';
import type { AddressInfo } from 'node:net';
import path from 'node:path';
import pg from 'pg';
import Redis from 'ioredis';

import {
  BPC_HA_SCHEMA, BPC_TRANSPORT_NONCE_SCHEMA, HA_OUTBOX_PG_SCHEMA,
  BpcCutoverController, BpcRedisQuorumFenceStore, HttpOutboxTransport, NodePostgresTransactor,
  PgDurableOutbox, PgDurablePublisher, PgPairMutationApplier, PgReceiverCheckpoint, PgReplayNonceStore, PgRedisFenceWitness,
  PgSourceLeaseFence, assertSchemaReady, createHaPairAuthority,
  bpcPairMutationSanitizer, buildPairSnapshotBundle, createHttpOutboxReceiver,
  buildPromotionReadinessAttestation, importPairSnapshotBundle, installActiveCutoverReceipt, installSourceLeaseGrant, pairSnapshotManifestDigest, promoteReceiverToSource, provisionSchemaVersion,
  redisFenceRecordDigest, signRedisFenceRecord, signSourceLeaseGrant, type AckReceipt, type AckReceiptVerifier,
  type BpcPairMutation, type OutboxRecord, type ReceiverDecision,
} from './packages/server/dist/index.js';

const URL_A = process.env['BPC_TEST_POSTGRES_URL'];
const URL_B = process.env['BPC_TEST_POSTGRES_B_URL'];
const URL_CONTROL = process.env['BPC_TEST_POSTGRES_CONTROL_URL'];
const REDIS_URLS = process.env['BPC_TEST_REDIS_URLS']?.split(',').filter(Boolean) ?? [];
if (!URL_A || !URL_B || !URL_CONTROL || REDIS_URLS.length !== 3) throw new Error('A/B/control PostgreSQL URLs and exactly three BPC_TEST_REDIS_URLS are required');
if (URL_A === URL_B) throw new Error('A and B PostgreSQL URLs must differ');
const { Pool } = pg;
const poolA = new Pool({ connectionString: URL_A, max: 8 }); poolA.on('error', () => {});
const poolB = new Pool({ connectionString: URL_B, max: 8 }); poolB.on('error', () => {});
const poolControl = new Pool({ connectionString: URL_CONTROL, max: 4 }); poolControl.on('error', () => {});
const dbA = new NodePostgresTransactor(poolA as never);
const dbB = new NodePostgresTransactor(poolB as never);
const dbControl = new NodePostgresTransactor(poolControl as never);
const redisMembers = REDIS_URLS.map((url)=>{const r=new Redis(url,{maxRetriesPerRequest:1});r.on('error',()=>{});return r;});
const SID = 'bpc:pair:ha-final/v1';
const E1 = 'bpc-e:1', E2 = 'bpc-e:2';
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const sealKey = Buffer.alloc(32, 51);
const requestSecret = Buffer.alloc(32, 53), responseSecret = Buffer.alloc(32, 55), ackSecret = Buffer.alloc(32, 57);
const { publicKey: guardPublic, privateKey: guardPrivate } = generateKeyPairSync('ed25519');
const { publicKey: sourcePublic, privateKey: sourcePrivate } = generateKeyPairSync('ed25519');
const sourceResolver = { resolve: (keyId: string) => keyId === 'guard-v1' ? guardPublic : keyId==='source-v1'?sourcePublic:null };
const keyring = { activeKeyId: 'seal-v1', resolveKey: (keyId: string) => { if (keyId !== 'seal-v1') throw new Error('unknown seal key'); return sealKey; } };

async function ddl(pool: pg.Pool, sql: string): Promise<void> {
  for (const statement of sql.split(';').map((part) => part.trim()).filter(Boolean)) await pool.query(statement);
}
async function reset(pool: pg.Pool): Promise<void> {
  await pool.query('DROP SCHEMA IF EXISTS bpc_ha CASCADE');
  await pool.query('DROP TABLE IF EXISTS bpc_transport_nonce,bpc_pending,bpc_pairs,ha_outbox_rows,ha_outbox_applied,ha_outbox_fence,ha_outbox_source_checkpoint,ha_outbox_receiver_checkpoint,ha_outbox_publisher_lease,ha_outbox_quarantine,ha_outbox_meta CASCADE');
  await ddl(pool, HA_OUTBOX_PG_SCHEMA); await ddl(pool, BPC_TRANSPORT_NONCE_SCHEMA); await pool.query(BPC_HA_SCHEMA);
}
const systemId = async (pool: pg.Pool) => String((await pool.query('SELECT system_identifier::text AS id FROM pg_control_system()')).rows[0].id);
const pair = (n: number) => ({
  id:`pair-${n}`, name:`Pair ${n}`, scope:'read' as const, mode:'production' as const,
  secretHash:Buffer.alloc(32,n).toString('base64url'),
  pubJwk:{kty:'EC',crv:'P-256',x:Buffer.alloc(32,n+1).toString('base64url'),y:Buffer.alloc(32,n+2).toString('base64url')},
  status:'active' as const, created:1_800_000_000_000+n, lastActive:null, requests:0, failedSigs:0,
});
const ackBody = (a: Omit<AckReceipt, 'signature'>) => [a.receiverId,a.keyId,a.streamId,a.sourceEpoch,a.sequence,a.opDigest,a.decision,a.issuedAt].join('|');
const receiptFor = (record: OutboxRecord<unknown>, decision: ReceiverDecision): AckReceipt => {
  const bare: Omit<AckReceipt,'signature'> = { streamId:record.streamId,sourceEpoch:record.sourceEpoch,sequence:record.sequence,opDigest:record.opDigest,decision,receiverId:'receiver-b',keyId:'ack-v1',issuedAt:String(Date.now()) };
  return { ...bare, signature:createHmac('sha256',ackSecret).update(ackBody(bare)).digest('base64url') };
};
const ackVerifier: AckReceiptVerifier = { async verify(receipt, record) {
  if (receipt.receiverId !== 'receiver-b' || receipt.keyId !== 'ack-v1' || receipt.streamId !== record.streamId || receipt.sourceEpoch !== record.sourceEpoch || receipt.sequence !== record.sequence || receipt.opDigest !== record.opDigest) throw new Error('ack binding invalid');
  const got=Buffer.from(receipt.signature,'base64url'), want=createHmac('sha256',ackSecret).update(ackBody(receipt)).digest();
  if(got.length!==want.length||!timingSafeEqual(got,want))throw new Error('ack signature invalid');
} };

function workerEnv(mode: string, receiverUrl: string, leaseBinding?: object, redisProbeUrl?: string): NodeJS.ProcessEnv {
  return { ...process.env, BPC_HA_WORKER_MODE:mode, BPC_HA_PG_URL:URL_A, BPC_HA_STREAM_ID:SID,
    BPC_HA_RECEIVER_URL:receiverUrl, BPC_HA_REQUEST_SECRET:requestSecret.toString('base64url'),
    BPC_HA_RESPONSE_SECRET:responseSecret.toString('base64url'), BPC_HA_ACK_SECRET:ackSecret.toString('base64url'),
    BPC_HA_LEASE_BINDING:leaseBinding ? JSON.stringify(leaseBinding) : undefined,
    BPC_HA_GUARD_PUBLIC_KEY:guardPublic.export({type:'spki',format:'pem'}).toString(),
    BPC_HA_SEAL_KEY:sealKey.toString('base64url'), BPC_HA_REDIS_PROBE_URL:redisProbeUrl,
    BPC_HA_REDIS_URLS:redisProbeUrl ? [redisProbeUrl,redisProbeUrl,redisProbeUrl].join(',') : REDIS_URLS.join(','),BPC_HA_CONTROL_PG_URL:URL_CONTROL };
}
function spawnWorker(env: NodeJS.ProcessEnv): ChildProcess {
  return spawn(process.execPath, ['--import','tsx',path.resolve('bpc-ha-worker.mts')], { cwd:process.cwd(), env, stdio:['ignore','pipe','pipe'] });
}
async function runWorker(env: NodeJS.ProcessEnv): Promise<Record<string, unknown>> {
  const child=spawnWorker(env); let out='',err=''; child.stdout!.on('data',(d)=>out+=d);child.stderr!.on('data',(d)=>err+=d);
  const code=await new Promise<number|null>((resolve)=>child.on('exit',resolve));
  if(code!==0)throw new Error(`worker failed (${code}): ${err||out}`);
  return JSON.parse(out.trim().split(/\r?\n/).at(-1)!);
}
async function startRedisProxy(): Promise<{url:string; partition:()=>Promise<void>}> {
  const target=new URL(REDIS_URLS[0]!); const sockets=new Set<net.Socket>();
  const server=net.createServer((client)=>{sockets.add(client);const upstream=net.connect(Number(target.port||6379),target.hostname);sockets.add(upstream);client.pipe(upstream).pipe(client);const close=()=>{sockets.delete(client);sockets.delete(upstream);client.destroy();upstream.destroy();};client.on('error',close);upstream.on('error',close);client.on('close',close);upstream.on('close',close);});
  await new Promise<void>((resolve)=>server.listen(0,'127.0.0.1',resolve)); const port=(server.address() as AddressInfo).port;
  return {url:`redis://127.0.0.1:${port}`,partition:async()=>{for(const socket of sockets)socket.destroy();await new Promise<void>((resolve)=>server.close(()=>resolve()));}};
}

let server: Server | null = null;
async function main(): Promise<void> {
  await Promise.all(redisMembers.map(r=>r.flushdb())); await reset(poolA); await reset(poolB); await reset(poolControl);
  const idA=await systemId(poolA), idB=await systemId(poolB), idControl=await systemId(poolControl); assert.equal(new Set([idA,idB,idControl]).size,3);
  const readyA=await provisionSchemaVersion(dbA,'public'); let readyB=await provisionSchemaVersion(dbB,'public');
  await poolA.query('INSERT INTO ha_outbox_fence(stream_id,fence_token) VALUES($1,1)',[SID]);
  await poolA.query('INSERT INTO ha_outbox_source_checkpoint(stream_id,source_epoch,sequence) VALUES($1,$2,0)',[SID,E1]);
  await poolB.query('INSERT INTO ha_outbox_fence(stream_id,fence_token) VALUES($1,1)',[SID]);
  await poolB.query('INSERT INTO ha_outbox_receiver_checkpoint(stream_id,source_epoch,sequence) VALUES($1,$2,0)',[SID,E1]);

  const fenceStore=await BpcRedisQuorumFenceStore.open(redisMembers,sourceResolver,await PgRedisFenceWitness.open(dbControl,sourceResolver),'bpc:ha:final');
  const redisA=signRedisFenceRecord('guard-v1',guardPrivate,{streamId:SID,epoch:1,nodeId:'node-a',commandId:'activate-a',claimedAtMs:Date.now()});
  assert.equal(await fenceStore.claim(redisA),true);
  const quorumFaultAt=Date.now();redisMembers[2]!.disconnect();assert.equal((await fenceStore.current()).epoch,1);
  redisMembers[1]!.disconnect();await assert.rejects(fenceStore.current(),/no authoritative majority/);
  await redisMembers[1]!.connect();await redisMembers[2]!.connect();assert.equal((await fenceStore.current()).epoch,1);const quorumRecoveryMs=Date.now()-quorumFaultAt;
  await poolControl.query('INSERT INTO bpc_ha.epoch_witness(stream_id,epoch,state_digest) VALUES($1,1,$2)',[SID,redisFenceRecordDigest(redisA)]);
  const aLeaseExpiry=Date.now()+6_000;
  const grant1=signSourceLeaseGrant('guard-v1',guardPrivate,{streamId:SID,epoch:1,status:'active',holderNodeId:'node-a',leaseId:'lease-a',commandId:'grant-a1',expiresAtMs:aLeaseExpiry,grantSeq:1,prevDigest:null});
  await dbA.transaction((exec)=>installSourceLeaseGrant(exec,sourceResolver,grant1));await dbControl.transaction((exec)=>installSourceLeaseGrant(exec,sourceResolver,grant1));
  const binding1={streamId:SID,epoch:1,holderNodeId:'node-a',leaseId:'lease-a',grantDigest:grant1.grantDigest,redisClaimDigest:redisFenceRecordDigest(redisA),maxClockSkewMs:25};
  const makeStoreA=async(binding:typeof binding1)=>createHaPairAuthority(dbA,readyA,{streamId:SID,fenceToken:1n,keyring,maxPendingRows:100},await PgSourceLeaseFence.open(dbA,sourceResolver,binding,fenceStore));
  let storeA=await makeStoreA(binding1);

  let receiver=new PgReceiverCheckpoint<BpcPairMutation>(dbB,SID,bpcPairMutationSanitizer,new PgPairMutationApplier(SID,keyring),readyB);
  const nonceStore=await PgReplayNonceStore.open(dbB,'public'); let holdAck=false; let releaseAck:()=>void=()=>{};
  let ackGate=new Promise<void>((resolve)=>{releaseAck=resolve;});
  const handler=createHttpOutboxReceiver({expectedPath:'/ingest',resolveRequestKey:(keyId)=>keyId==='request-v1'?requestSecret:null,responseKeyId:'response-v1',responseSecret,nonceStore,receive:async(record)=>{const decision=await receiver.verifyAndApplyDelivered(record as OutboxRecord<BpcPairMutation>);if(holdAck)await ackGate;return receiptFor(record,decision);}});
  server=createServer((req,res)=>handler(req,res));await new Promise<void>((resolve)=>server!.listen(0,'127.0.0.1',resolve));
  const receiverUrl=`http://127.0.0.1:${(server.address() as AddressInfo).port}/ingest`;
  const transport=new HttpOutboxTransport({url:receiverUrl,fetch:fetch as never,requestKeyId:'request-v1',requestSecret,resolveResponseKey:(keyId)=>keyId==='response-v1'?responseSecret:null,ackVerifier,timeoutMs:10_000});
  const publisher=()=>new PgDurablePublisher(dbA,SID,transport,'fail-authoritative-mutation',bpcPairMutationSanitizer,ackVerifier,readyA,{leaseMs:2_000});
  const drain=async()=>{for(let i=0;i<20;i++){await publisher().drainOnce();const n=Number((await poolA.query('SELECT count(*)::int n FROM ha_outbox_rows WHERE stream_id=$1 AND acked_at IS NULL AND quarantined_at IS NULL',[SID])).rows[0].n);if(n===0)return;await sleep(50);}throw new Error('drain did not converge');};

  await storeA.set(pair(1)); await drain();

  // Actual publisher process death after B committed but before its ACK reached A.
  await storeA.set(pair(2)); holdAck=true; ackGate=new Promise<void>((resolve)=>{releaseAck=resolve;});
  const crashed=spawnWorker(workerEnv('publisher',receiverUrl)); let crashErr='';crashed.stderr!.on('data',(d)=>crashErr+=d);
  for(let i=0;i<100;i++){const seq=Number((await poolB.query('SELECT sequence FROM ha_outbox_receiver_checkpoint WHERE stream_id=$1',[SID])).rows[0].sequence);if(seq===2)break;await sleep(25);if(i===99)throw new Error(`child never delivered before crash: ${crashErr}`);}
  const crashAt=Date.now(); crashed.kill('SIGKILL'); await new Promise((resolve)=>crashed.on('exit',resolve)); holdAck=false;releaseAck();
  const crashBacklog=Number((await poolA.query('SELECT count(*)::int n FROM ha_outbox_rows WHERE stream_id=$1 AND acked_at IS NULL',[SID])).rows[0].n);assert.equal(crashBacklog,1);
  await sleep(2_100); const restart=await runWorker(workerEnv('publisher',receiverUrl));assert.equal((restart.result as {acked:number}).acked,1);
  const crashRtoMs=Date.now()-crashAt;assert.equal(Number((await poolA.query('SELECT count(*)::int n FROM ha_outbox_rows WHERE stream_id=$1 AND acked_at IS NULL',[SID])).rows[0].n),0);
  assert.equal(Number((await poolB.query('SELECT count(*)::int n FROM ha_outbox_applied WHERE stream_id=$1',[SID])).rows[0].n),2);

  await storeA.set(pair(3)); await drain();
  // Capture C=3, discard the old receiver authority, and bootstrap a genuinely
  // fresh B solely from the signed source snapshot.
  const snapshotAtC=await buildPairSnapshotBundle<BpcPairMutation>(dbA,SID,3,'source-v1',sourcePrivate);
  await reset(poolB);readyB=await provisionSchemaVersion(dbB,'public');
  await poolB.query('INSERT INTO ha_outbox_fence(stream_id,fence_token) VALUES($1,1)',[SID]);
  await poolB.query('INSERT INTO ha_outbox_receiver_checkpoint(stream_id,source_epoch,sequence) VALUES($1,$2,0)',[SID,E1]);
  receiver=new PgReceiverCheckpoint<BpcPairMutation>(dbB,SID,bpcPairMutationSanitizer,new PgPairMutationApplier(SID,keyring),readyB);
  await importPairSnapshotBundle(dbB,sourceResolver,snapshotAtC,bpcPairMutationSanitizer,new PgPairMutationApplier(SID,keyring));
  assert.equal(Number((await poolB.query('SELECT sequence FROM ha_outbox_receiver_checkpoint WHERE stream_id=$1',[SID])).rows[0].sequence),3);
  const tampered=structuredClone(snapshotAtC);(tampered.records[0] as {opDigest:string}).opDigest='0'.repeat(64);
  await assert.rejects(importPairSnapshotBundle(dbB,sourceResolver,tampered,bpcPairMutationSanitizer,new PgPairMutationApplier(SID,keyring)),/digest|empty pair authority/);
  const grant2=signSourceLeaseGrant('guard-v1',guardPrivate,{streamId:SID,epoch:1,status:'active',holderNodeId:'node-a',leaseId:'lease-a',commandId:'renew-a2',expiresAtMs:aLeaseExpiry,grantSeq:2,prevDigest:grant1.grantDigest});
  await dbA.transaction((exec)=>installSourceLeaseGrant(exec,sourceResolver,grant2));await dbControl.transaction((exec)=>installSourceLeaseGrant(exec,sourceResolver,grant2));
  const binding2={...binding1,grantDigest:grant2.grantDigest}; storeA=await makeStoreA(binding2);
  await storeA.set(pair(4));await storeA.set(pair(5));await storeA.set(pair(6));

  // Begin a mutation while the lease is valid, revoke it after caller DML has
  // executed, then release the callback. The real pre-commit hook must reject
  // and roll back both the probe DML and outbox append.
  await poolA.query('CREATE TABLE IF NOT EXISTS bpc_ha.precommit_probe(id int primary key)');
  const liveFence=await PgSourceLeaseFence.open(dbA,sourceResolver,binding2,fenceStore);
  const guardedOutbox=new PgDurableOutbox(dbA,readyA,{streamId:SID,sanitizer:bpcPairMutationSanitizer,maxPendingRows:100,backpressure:'fail-authoritative-mutation',preCommitCheck:(exec)=>liveFence.assertWritableInTx(exec)});
  let entered!:()=>void,released!:()=>void;const enteredP=new Promise<void>(r=>entered=r),releaseP=new Promise<void>(r=>released=r);
  const inFlight=guardedOutbox.withOutboxTx(async(tx,exec)=>{await guardedOutbox.appendInTx(tx,{streamId:SID,rawMutation:{kind:'bpc.pair.delete.v1',pairId:'precommit-probe'},fenceToken:1n});await exec.query('INSERT INTO bpc_ha.precommit_probe(id) VALUES(1)');entered();await releaseP;});
  await enteredP;const revokedA=signSourceLeaseGrant('guard-v1',guardPrivate,{streamId:SID,epoch:1,status:'revoked',holderNodeId:'node-a',leaseId:'lease-a',commandId:'revoke-a3',expiresAtMs:grant2.expiresAtMs,grantSeq:3,prevDigest:grant2.grantDigest});
  await dbA.transaction(exec=>installSourceLeaseGrant(exec,sourceResolver,revokedA));await dbControl.transaction(exec=>installSourceLeaseGrant(exec,sourceResolver,revokedA));released();await assert.rejects(inFlight,/stale|revoked|serialize|concurrent update/);assert.equal(Number((await poolA.query('SELECT count(*)::int n FROM bpc_ha.precommit_probe')).rows[0].n),0);

  // Live Redis partition: old A can still reach A-PG, but its control-issued
  // lease expires and the in-tx pre-commit gate refuses the write.
  const redisProxy=await startRedisProxy(); const probe=new Redis(redisProxy.url,{connectTimeout:500,maxRetriesPerRequest:0,retryStrategy:()=>null});await probe.ping();probe.disconnect();await redisProxy.partition();
  const cutoverAt=Date.now(); await sleep(Math.max(0,aLeaseExpiry-Date.now()+75));
  const bundle=await buildPairSnapshotBundle<BpcPairMutation>(dbA,SID,6,'source-v1',sourcePrivate);
  assert.equal(bundle.manifest.finalSequence,6);
  const tailAtCutover=bundle.manifest.finalSequence-Number((await poolB.query('SELECT sequence FROM ha_outbox_receiver_checkpoint WHERE stream_id=$1',[SID])).rows[0].sequence);assert.equal(tailAtCutover,3);

  const redisB=signRedisFenceRecord('guard-v1',guardPrivate,{streamId:SID,epoch:2,nodeId:'node-b',commandId:'promote-b',claimedAtMs:Date.now()});
  const controller=new BpcCutoverController(dbControl,sourceResolver,'guard-v1',guardPrivate,25);
  await controller.begin({streamId:SID,commandId:'promote-b',previousEpoch:1,targetEpoch:2,targetNodeId:'node-b',targetSourceEpoch:E2,manifestDigest:pairSnapshotManifestDigest(bundle.manifest),finalSourceSequence:bundle.manifest.finalSequence,stateDigest:bundle.manifest.stateDigest,redisClaimDigest:redisFenceRecordDigest(redisB),oldLeaseDigest:revokedA.grantDigest,oldLeaseExpiresAtMs:revokedA.expiresAtMs});
  assert.equal(await fenceStore.claim(redisB),true);
  const fenced=await controller.markFenced('promote-b',fenceStore);

  await drain(); const resyncMs=Date.now()-cutoverAt;
  assert.equal(Number((await poolB.query('SELECT sequence FROM ha_outbox_receiver_checkpoint WHERE stream_id=$1',[SID])).rows[0].sequence),6);
  const evil=signRedisFenceRecord('guard-v1',guardPrivate,{streamId:SID,epoch:2,nodeId:'evil',commandId:'split-brain',claimedAtMs:Date.now()});
  await assert.rejects(fenceStore.claim(evil),/conflicting|disagrees|rollback|future/);
  const grantB=signSourceLeaseGrant('guard-v1',guardPrivate,{streamId:SID,epoch:2,status:'active',holderNodeId:'node-b',leaseId:'lease-b',commandId:'grant-b1',expiresAtMs:Date.now()+60_000,grantSeq:1,prevDigest:null});
  await dbB.transaction((exec)=>installSourceLeaseGrant(exec,sourceResolver,grantB));
  await promoteReceiverToSource(dbB,sourceResolver,bundle,bpcPairMutationSanitizer,2,E2,sourceResolver,fenced);
  const readiness=await buildPromotionReadinessAttestation(dbB,fenced,'source-v1',sourcePrivate);const active=await controller.markActive('promote-b',readiness,sourceResolver);await installActiveCutoverReceipt(dbB,sourceResolver,active);
  const bindingB={streamId:SID,epoch:2,holderNodeId:'node-b',leaseId:'lease-b',grantDigest:grantB.grantDigest,redisClaimDigest:redisFenceRecordDigest(redisB),maxClockSkewMs:25,activationDigest:active.stateDigestSigned};
  const storeB=createHaPairAuthority(dbB,readyB,{streamId:SID,fenceToken:2n,keyring,maxPendingRows:100},await PgSourceLeaseFence.open(dbB,sourceResolver,bindingB,fenceStore));
  await storeB.set(pair(7)); const promotionRtoMs=Date.now()-cutoverAt;
  const rollbackAt=Date.now();await redisMembers[1]!.set('bpc:ha:final',JSON.stringify(redisA));await redisMembers[2]!.set('bpc:ha:final',JSON.stringify(redisA));
  await assert.rejects(fenceStore.current(),/rollback|disagrees|future/);await assert.rejects(storeB.set(pair(8)),/rollback|disagrees|future/);assert.equal(Number((await poolB.query("SELECT count(*)::int n FROM bpc_pairs WHERE id='pair-8'")).rows[0].n),0);
  await redisMembers[1]!.set('bpc:ha:final',JSON.stringify(redisB));await redisMembers[2]!.set('bpc:ha:final',JSON.stringify(redisB));await storeB.set(pair(8));const rollbackRecoveryMs=Date.now()-rollbackAt;

  const stale=await runWorker(workerEnv('stale-writer',receiverUrl,binding2,redisProxy.url));
  assert.equal(stale.denied,true);assert.equal(stale.redisPartitionObserved,true);
  assert.equal(Number((await poolA.query("SELECT count(*)::int n FROM bpc_pairs WHERE id='stale-writer'")).rows[0].n),0);
  assert.equal(String((await fenceStore.current())?.nodeId),'node-b');
  assert.equal(Number((await poolB.query('SELECT sequence FROM ha_outbox_source_checkpoint WHERE stream_id=$1',[SID])).rows[0].sequence),2);
  assert.equal(Number((await poolB.query('SELECT count(*)::int n FROM bpc_ha.promotion_receipt WHERE stream_id=$1 AND target_epoch=2',[SID])).rows[0].n),1);
  assert.deepEqual((await poolA.query('SELECT id FROM bpc_pairs ORDER BY id')).rows,(await poolB.query("SELECT id FROM bpc_pairs WHERE id NOT IN ('pair-7','pair-8') ORDER BY id")).rows);

  console.log('# BPC #16 frozen HA acceptance');
  console.log(`  distinct PostgreSQL system identifiers: A=${idA} B=${idB} control=${idControl}`);
  console.log(`  process-SIGKILL: backlog-at-fault=${crashBacklog}, data-loss-RPO=0, RTO=${crashRtoMs}ms`);
  console.log(`  Redis quorum: one member unavailable remained readable; two unavailable failed closed; recovery=${quorumRecoveryMs}ms`);
  console.log(`  live Redis partition + frozen-A snapshot/tail: tail=${tailAtCutover}, data-loss-RPO=0, resync=${resyncMs}ms`);
  console.log(`  promotion: B writable at epoch=2 and originated N+1, RTO=${promotionRtoMs}ms`);
  console.log(`  Redis majority rollback: new source failed closed; exact signed quorum restore recovered in ${rollbackRecoveryMs}ms`);
  console.log('  split-brain: signed equal-epoch competing quorum claim rejected; partitioned old A write refused in its PostgreSQL pre-commit gate');
}

try { await main(); }
finally { if(server)await new Promise<void>((resolve)=>server!.close(()=>resolve()));await poolA.end().catch(()=>{});await poolB.end().catch(()=>{});await poolControl.end().catch(()=>{});for(const redis of redisMembers)redis.disconnect();sealKey.fill(0);requestSecret.fill(0);responseSecret.fill(0);ackSecret.fill(0); }
