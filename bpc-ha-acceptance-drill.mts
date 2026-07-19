/**
 * Frozen BPC #16 acceptance: real A/B PostgreSQL authorities, real Redis
 * external fencing, authenticated network replication, actual publisher
 * SIGKILL/restart, expiring-lease old-writer refusal under a live Redis
 * partition, snapshot+tail resync, promotion, and measured per-fault RPO/RTO.
 */
import assert from 'node:assert/strict';
import { createHash, createHmac, generateKeyPairSync, timingSafeEqual } from 'node:crypto';
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
  provisionBpcHaSchema,
  assertBpcHaSchemaReady, provisionBpcRuntimeMutationBoundary,
  validateDbMutationPolicyContext,
  canonicalOpDigest,
  Aes256GcmPairPayloadCodec,
  redisFenceRecordDigest, signRedisFenceRecord, signSourceLeaseGrant, type AckReceipt, type AckReceiptVerifier,
  signNodeIdentityChallenge,
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
let poolRuntimeA:pg.Pool|null=null;
let poolRuntimeB:pg.Pool|null=null;
const dbA = new NodePostgresTransactor(poolA as never,{statementTimeoutMs:800,transactionTimeoutMs:1_000});
const dbB = new NodePostgresTransactor(poolB as never);
const dbControl = new NodePostgresTransactor(poolControl as never);
const redisMembers = REDIS_URLS.map((url)=>{const r=new Redis(url,{maxRetriesPerRequest:1});r.on('error',()=>{});return r;});
const SID = 'bpc:pair:ha-final/v1';
const E1 = 'bpc-e:1', E2 = 'bpc-e:2';
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const runtimeConnection=(base:string)=>{const value=new URL(base);value.username='bpc_runtime_acceptance';value.password='bpc-runtime-test-only';return value.toString();};
const sealKey = Buffer.alloc(32, 51);
const mutationTicketSecret=Buffer.alloc(32,59);const mutationTicketSigner={keyId:'mutation-v1',async signTicket(request:Record<string,string>,context:{canonicalPolicy:string}){validateDbMutationPolicyContext(request as never,context,new Aes256GcmPairPayloadCodec('seal-v1',keyring.resolveKey));return createHmac('sha256',mutationTicketSecret).update([request.domain,request.keyId,request.nonce,request.streamId,request.epoch,request.leaseId,request.grantDigest,request.txid,request.expiresAtMs,request.sourceEpoch,request.sequence,request.opDigest,request.action,request.payloadDigest,request.policyDigest].join('|')).digest('hex');}};
const requestSecret = Buffer.alloc(32, 53), responseSecret = Buffer.alloc(32, 55), ackSecret = Buffer.alloc(32, 57);
const { publicKey: guardPublic, privateKey: guardPrivate } = generateKeyPairSync('ed25519');
const { publicKey: sourcePublic, privateKey: sourcePrivate } = generateKeyPairSync('ed25519');
const {publicKey:nodeAPublic,privateKey:nodeAPrivate}=generateKeyPairSync('ed25519');const {publicKey:nodeBPublic,privateKey:nodeBPrivate}=generateKeyPairSync('ed25519');
const sourceResolver = { resolve: (keyId: string) => keyId === 'guard-v1'||keyId==='guard-alias' ? guardPublic : keyId==='source-v1'?sourcePublic:keyId==='node-a-hsm'?nodeAPublic:keyId==='node-b-hsm'?nodeBPublic:null };
const nodeAIdentity={keyId:'node-a-hsm',prove:async(challenge:Uint8Array)=>signNodeIdentityChallenge('node-a-hsm',nodeAPrivate,challenge)};const nodeBIdentity={keyId:'node-b-hsm',prove:async(challenge:Uint8Array)=>signNodeIdentityChallenge('node-b-hsm',nodeBPrivate,challenge)};
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
  return { ...process.env, BPC_HA_WORKER_MODE:mode, BPC_HA_PG_URL:mode==='stale-writer'?runtimeConnection(URL_A):URL_A, BPC_HA_STREAM_ID:SID,
    BPC_HA_RECEIVER_URL:receiverUrl, BPC_HA_REQUEST_SECRET:requestSecret.toString('base64url'),
    BPC_HA_RESPONSE_SECRET:responseSecret.toString('base64url'), BPC_HA_ACK_SECRET:ackSecret.toString('base64url'),
    BPC_HA_LEASE_BINDING:leaseBinding ? JSON.stringify(leaseBinding) : undefined,
    BPC_HA_TRANSACTION_TIMEOUT_MS:leaseBinding ? String((leaseBinding as {maxTransactionDurationMs:number}).maxTransactionDurationMs) : undefined,
    BPC_HA_GUARD_PUBLIC_KEY:guardPublic.export({type:'spki',format:'pem'}).toString(),
    BPC_HA_NODE_PUBLIC_KEY:nodeAPublic.export({type:'spki',format:'pem'}).toString(),BPC_HA_NODE_PRIVATE_KEY:nodeAPrivate.export({type:'pkcs8',format:'pem'}).toString(),
    BPC_HA_SEAL_KEY:sealKey.toString('base64url'), BPC_HA_REDIS_PROBE_URL:redisProbeUrl,
    BPC_HA_MUTATION_TICKET_SECRET:mutationTicketSecret.toString('base64url'),
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
  const policyMutation={kind:'bpc.pair.delete.v1',pairId:'pair-a'},wrongIdentityPolicy=JSON.stringify({action:'pair-delete',mutation:policyMutation,payload:['pair-b'],streamId:'policy-stream',sourceEpoch:'policy-epoch',sequence:'1',fenceToken:'1'}),policyHeader={domain:'bpc-db-mutation/v1',keyId:'mutation-v1',nonce:'n',streamId:'policy-stream',epoch:'1',leaseId:'l',grantDigest:'0'.repeat(64),txid:'1',expiresAtMs:'1',sourceEpoch:'policy-epoch',sequence:'1',opDigest:canonicalOpDigest({streamId:'policy-stream',sourceEpoch:'policy-epoch',sequence:1,fenceToken:'1',mutation:policyMutation as never}),action:'pair-delete',payloadDigest:'0'.repeat(64),policyDigest:createHash('sha256').update(wrongIdentityPolicy).digest('hex')},policyCodec=new Aes256GcmPairPayloadCodec('seal-v1',keyring.resolveKey);assert.throws(()=>validateDbMutationPolicyContext(policyHeader as never,{canonicalPolicy:wrongIdentityPolicy},policyCodec),/payload mapping/);const rightIdentityPolicy=wrongIdentityPolicy.replace('pair-b','pair-a');assert.throws(()=>validateDbMutationPolicyContext({...policyHeader,opDigest:'f'.repeat(64),policyDigest:createHash('sha256').update(rightIdentityPolicy).digest('hex')} as never,{canonicalPolicy:rightIdentityPolicy},policyCodec),/opDigest mismatch/);
  const sourcePair=pair(99),sealed=policyCodec.sealPair(sourcePair as never,{domain:'bpc-pair-payload',version:'1',streamId:'policy-stream',kind:'bpc.pair.set.v1',pairId:sourcePair.id}),setMutation={kind:'bpc.pair.set.v1',pairId:sourcePair.id,sealed},wrongFields=[sourcePair.id,'ATTACKER NAME',sourcePair.scope,sourcePair.mode,sourcePair.secretHash,JSON.stringify(sourcePair.pubJwk),sourcePair.status,sourcePair.created,sourcePair.lastActive,sourcePair.requests,sourcePair.failedSigs,null,null,null,'legitimate',null,null],wrongFieldsPolicy=JSON.stringify({action:'pair-upsert',mutation:setMutation,payload:wrongFields,streamId:'policy-stream',sourceEpoch:'policy-epoch',sequence:'1',fenceToken:'1'}),setHeader={...policyHeader,action:'pair-upsert',opDigest:canonicalOpDigest({streamId:'policy-stream',sourceEpoch:'policy-epoch',sequence:1,fenceToken:'1',mutation:setMutation as never}),policyDigest:createHash('sha256').update(wrongFieldsPolicy).digest('hex')};assert.throws(()=>validateDbMutationPolicyContext(setHeader as never,{canonicalPolicy:wrongFieldsPolicy},policyCodec),/complete DML payload/);const malformedMutation={...policyMutation,extra:'forbidden'},malformedPolicy=JSON.stringify({action:'pair-delete',mutation:malformedMutation,payload:['pair-a'],streamId:'policy-stream',sourceEpoch:'policy-epoch',sequence:'1',fenceToken:'1'});assert.throws(()=>validateDbMutationPolicyContext({...policyHeader,opDigest:canonicalOpDigest({streamId:'policy-stream',sourceEpoch:'policy-epoch',sequence:1,fenceToken:'1',mutation:malformedMutation as never}),policyDigest:createHash('sha256').update(malformedPolicy).digest('hex')} as never,{canonicalPolicy:malformedPolicy},policyCodec),/unexpected field/);
  await Promise.all(redisMembers.map(r=>r.flushdb())); await reset(poolA); await reset(poolB); await reset(poolControl);
  const idA=await systemId(poolA), idB=await systemId(poolB), idControl=await systemId(poolControl); assert.equal(new Set([idA,idB,idControl]).size,3);
  const readyA=await provisionSchemaVersion(dbA,'public'); let readyB=await provisionSchemaVersion(dbB,'public');const haReadyA=await provisionBpcHaSchema(dbA);let haReadyB=await provisionBpcHaSchema(dbB);const haReadyControl=await provisionBpcHaSchema(dbControl);await poolA.query('INSERT INTO bpc_ha.mutation_ticket_key(key_id,secret) VALUES($1,$2)',['mutation-v1',mutationTicketSecret]);await poolB.query('INSERT INTO bpc_ha.mutation_ticket_key(key_id,secret) VALUES($1,$2)',['mutation-v1',mutationTicketSecret]);
  await poolA.query("DO $$ BEGIN IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='bpc_runtime_acceptance') THEN REASSIGN OWNED BY bpc_runtime_acceptance TO bpc_test; DROP OWNED BY bpc_runtime_acceptance; DROP ROLE bpc_runtime_acceptance; END IF; IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='bpc_runtime_bypass') THEN REASSIGN OWNED BY bpc_runtime_bypass TO bpc_test; DROP OWNED BY bpc_runtime_bypass; DROP ROLE bpc_runtime_bypass; END IF; CREATE ROLE bpc_runtime_acceptance LOGIN PASSWORD 'bpc-runtime-test-only'; CREATE ROLE bpc_runtime_bypass NOINHERIT; END $$");
  await poolA.query('GRANT SELECT ON bpc_ha.mutation_ticket_key TO bpc_runtime_bypass');await poolA.query('GRANT bpc_runtime_bypass TO bpc_runtime_acceptance');await assert.rejects(provisionBpcRuntimeMutationBoundary(dbA,'bpc_runtime_acceptance','mutation-v1',mutationTicketSecret),/membership retains/);await poolA.query('REVOKE bpc_runtime_bypass FROM bpc_runtime_acceptance');await poolA.query('REVOKE ALL ON bpc_ha.mutation_ticket_key FROM bpc_runtime_bypass');
  await provisionBpcRuntimeMutationBoundary(dbA,'bpc_runtime_acceptance','mutation-v1',mutationTicketSecret);
  const runtimeUrl=new URL(URL_A);runtimeUrl.username='bpc_runtime_acceptance';runtimeUrl.password='bpc-runtime-test-only';poolRuntimeA=new Pool({connectionString:runtimeUrl.toString(),max:4});poolRuntimeA.on('error',()=>{});const dbRuntimeA=new NodePostgresTransactor(poolRuntimeA as never,{statementTimeoutMs:800,transactionTimeoutMs:1_000});const readyRuntimeA=await assertSchemaReady(dbRuntimeA,'public');const haReadyRuntimeA=await assertBpcHaSchemaReady(dbRuntimeA);
  await poolB.query("DO $$ BEGIN IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='bpc_runtime_acceptance') THEN REASSIGN OWNED BY bpc_runtime_acceptance TO bpc_test; DROP OWNED BY bpc_runtime_acceptance; DROP ROLE bpc_runtime_acceptance; END IF; CREATE ROLE bpc_runtime_acceptance LOGIN PASSWORD 'bpc-runtime-test-only'; END $$");await provisionBpcRuntimeMutationBoundary(dbB,'bpc_runtime_acceptance','mutation-v1',mutationTicketSecret);const runtimeUrlB=new URL(URL_B);runtimeUrlB.username='bpc_runtime_acceptance';runtimeUrlB.password='bpc-runtime-test-only';poolRuntimeB=new Pool({connectionString:runtimeUrlB.toString(),max:4});poolRuntimeB.on('error',()=>{});const dbRuntimeB=new NodePostgresTransactor(poolRuntimeB as never);let readyRuntimeB=await assertSchemaReady(dbRuntimeB,'public');let haReadyRuntimeB=await assertBpcHaSchemaReady(dbRuntimeB);
  await assert.rejects(PgRedisFenceWitness.open(dbControl,haReadyA,sourceResolver),/schema-readiness capability/);
  const statusConstraint=String((await poolA.query("SELECT conname FROM pg_catalog.pg_constraint WHERE conrelid='bpc_ha.source_lease'::regclass AND contype='c' AND pg_catalog.pg_get_constraintdef(oid) LIKE '%status%'")).rows[0].conname);await poolA.query(`ALTER TABLE bpc_ha.source_lease DROP CONSTRAINT ${statusConstraint}`);await assert.rejects(provisionBpcHaSchema(dbA),/schema attestation failed/);await poolA.query(`ALTER TABLE bpc_ha.source_lease ADD CONSTRAINT ${statusConstraint} CHECK (status IN ('active','revoked'))`);
  await poolA.query('INSERT INTO ha_outbox_fence(stream_id,fence_token) VALUES($1,1)',[SID]);
  await poolA.query('INSERT INTO ha_outbox_source_checkpoint(stream_id,source_epoch,sequence) VALUES($1,$2,0)',[SID,E1]);
  await poolB.query('INSERT INTO ha_outbox_fence(stream_id,fence_token) VALUES($1,1)',[SID]);
  await poolB.query('INSERT INTO ha_outbox_receiver_checkpoint(stream_id,source_epoch,sequence) VALUES($1,$2,0)',[SID,E1]);

  const redisWitness=await PgRedisFenceWitness.open(dbControl,haReadyControl,sourceResolver);
  const fenceStore=await BpcRedisQuorumFenceStore.open(redisMembers,sourceResolver,redisWitness,'bpc:ha:final');
  const redisA=signRedisFenceRecord('guard-v1',guardPrivate,{streamId:SID,epoch:1,nodeId:'node-a',authoritySystemId:idA,nodeCredentialKeyId:'node-a-hsm',commandId:'activate-a',claimedAtMs:Date.now()});
  await redisWitness.bootstrapGenesis(redisA);
  assert.equal(await fenceStore.claim(redisA),true);
  const quorumFaultAt=Date.now();redisMembers[2]!.disconnect();assert.equal((await fenceStore.current()).epoch,1);
  redisMembers[1]!.disconnect();await assert.rejects(fenceStore.current(),/no authoritative majority/);
  await redisMembers[1]!.connect();await redisMembers[2]!.connect();assert.equal((await fenceStore.current()).epoch,1);const quorumRecoveryMs=Date.now()-quorumFaultAt;
  const aLeaseExpiry=Date.now()+6_000;
  const grant1=signSourceLeaseGrant('guard-v1',guardPrivate,{streamId:SID,epoch:1,status:'active',holderNodeId:'node-a',leaseId:'lease-a',commandId:'grant-a1',expiresAtMs:aLeaseExpiry,maxTransactionDurationMs:dbA.maxTransactionDurationMs,grantSeq:1,prevDigest:null});
  await dbA.transaction((exec)=>installSourceLeaseGrant(exec,sourceResolver,grant1));await dbControl.transaction((exec)=>installSourceLeaseGrant(exec,sourceResolver,grant1));
  const binding1={streamId:SID,epoch:1,holderNodeId:'node-a',authoritySystemId:idA,nodeCredentialKeyId:'node-a-hsm',leaseId:'lease-a',grantDigest:grant1.grantDigest,redisClaimDigest:redisFenceRecordDigest(redisA),maxClockSkewMs:25,maxTransactionDurationMs:dbA.maxTransactionDurationMs};
  const makeStoreA=async(binding:typeof binding1)=>createHaPairAuthority(dbRuntimeA,readyRuntimeA,{streamId:SID,fenceToken:1n,keyring,maxPendingRows:100},await PgSourceLeaseFence.open(dbRuntimeA,haReadyRuntimeA,sourceResolver,binding,fenceStore,nodeAIdentity,mutationTicketSigner));
  let storeA=await makeStoreA(binding1);
  await assert.rejects(poolRuntimeA.query("INSERT INTO bpc_pairs(id,name,scope,mode,secret_hash,pub_jwk,status,created,last_active,requests,failed_sigs,kind) VALUES('bypass','x','read','production',$1,$2,'active',1,NULL,0,0,'legitimate')",[Buffer.alloc(32,1).toString('base64url'),pair(1).pubJwk]),/permission denied/);
  await assert.rejects(poolRuntimeA.query("UPDATE bpc_pairs SET status='revoked' WHERE id='missing'"),/permission denied/);await assert.rejects(poolRuntimeA.query("DELETE FROM bpc_pending WHERE token='missing'"),/permission denied/);
  await assert.rejects(poolRuntimeA.query("UPDATE ha_outbox_source_checkpoint SET sequence=99 WHERE stream_id=$1",[SID]),/permission denied/);await assert.rejects(poolRuntimeA.query("UPDATE ha_outbox_fence SET fence_token=99 WHERE stream_id=$1",[SID]),/permission denied/);await assert.rejects(poolRuntimeA.query("DELETE FROM ha_outbox_rows WHERE stream_id=$1",[SID]),/permission denied/);
  await assert.rejects(poolRuntimeA.query("SELECT bpc_ha.append_governed_outbox('{}'::jsonb,100,1,'{}'::jsonb)"),/invalid outbox ticket/i);
  await assert.rejects(poolRuntimeA.query("SELECT bpc_ha.apply_pair_mutation('{}'::jsonb,'pair-delete','[]'::jsonb)"),/mutation ticket|invalid controlled/i);
  await assert.rejects(poolRuntimeA.query('SELECT secret FROM bpc_ha.mutation_ticket_key'),/permission denied/);

  let receiver=new PgReceiverCheckpoint<BpcPairMutation>(dbB,SID,bpcPairMutationSanitizer,new PgPairMutationApplier(SID,keyring),readyB);
  const nonceStore=await PgReplayNonceStore.open(dbB,'public'); let holdAck=false; let releaseAck:()=>void=()=>{};
  let ackGate=new Promise<void>((resolve)=>{releaseAck=resolve;});
  const handler=createHttpOutboxReceiver({expectedPath:'/ingest',resolveRequestKey:(keyId)=>keyId==='request-v1'?requestSecret:null,responseKeyId:'response-v1',responseSecret,nonceStore,receive:async(record)=>{const decision=await receiver.verifyAndApplyDelivered(record as OutboxRecord<BpcPairMutation>);if(holdAck)await ackGate;return receiptFor(record,decision);}});
  server=createServer((req,res)=>handler(req,res));await new Promise<void>((resolve)=>server!.listen(0,'127.0.0.1',resolve));
  const receiverUrl=`http://127.0.0.1:${(server.address() as AddressInfo).port}/ingest`;
  const transport=new HttpOutboxTransport({url:receiverUrl,fetch:fetch as never,requestKeyId:'request-v1',requestSecret,resolveResponseKey:(keyId)=>keyId==='response-v1'?responseSecret:null,ackVerifier,timeoutMs:10_000});
  const publisher=()=>new PgDurablePublisher(dbA,SID,transport,'fail-authoritative-mutation',bpcPairMutationSanitizer,ackVerifier,readyA,{leaseMs:2_000});
  const drain=async()=>{for(let i=0;i<20;i++){await publisher().drainOnce();const n=Number((await poolA.query('SELECT count(*)::int n FROM ha_outbox_rows WHERE stream_id=$1 AND acked_at IS NULL AND quarantined_at IS NULL',[SID])).rows[0].n);if(n===0)return;await sleep(50);}throw new Error('drain did not converge');};

  await storeA.set(pair(1));assert.equal(Number((await poolA.query("SELECT count(*)::int n FROM bpc_pairs WHERE id='pair-1'")).rows[0].n),1);
  await poolA.query('GRANT UPDATE ON ha_outbox_source_checkpoint TO bpc_runtime_acceptance');await assert.rejects(storeA.set(pair(90)),/posture drifted/);await poolA.query('REVOKE UPDATE ON ha_outbox_source_checkpoint FROM bpc_runtime_acceptance');
  for(const table of ['ha_outbox_meta','ha_outbox_fence','ha_outbox_source_checkpoint','ha_outbox_receiver_checkpoint','ha_outbox_rows','ha_outbox_publisher_lease','ha_outbox_quarantine','ha_outbox_applied'])for(const privilege of ['INSERT','UPDATE','DELETE']){await poolA.query(`GRANT ${privilege} ON ${table} TO bpc_runtime_acceptance`);await assert.rejects(storeA.set(pair(92)),/posture drifted/);await poolA.query(`REVOKE ${privilege} ON ${table} FROM bpc_runtime_acceptance`);}
  for(const [privilege,table] of [['TRUNCATE','public.ha_outbox_rows'],['UPDATE','bpc_ha.mutation_ticket_key'],['DELETE','bpc_ha.mutation_ticket_nonce'],['UPDATE','bpc_ha.source_lease']] as const){await poolA.query(`GRANT ${privilege} ON ${table} TO bpc_runtime_acceptance`);await assert.rejects(storeA.set(pair(93)),/posture drifted/);await poolA.query(`REVOKE ${privilege} ON ${table} FROM bpc_runtime_acceptance`);}
  await poolA.query('GRANT EXECUTE ON FUNCTION bpc_ha.apply_pair_mutation(jsonb,text,jsonb) TO PUBLIC');await assert.rejects(storeA.set(pair(91)),/ownership\/ACL posture/);await poolA.query('REVOKE EXECUTE ON FUNCTION bpc_ha.apply_pair_mutation(jsonb,text,jsonb) FROM PUBLIC');
  assert.equal(Number((await poolA.query("SELECT count(*)::int n FROM bpc_pairs WHERE id IN ('pair-90','pair-91','pair-92','pair-93')")).rows[0].n),0);await drain();

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
  await poolRuntimeB.end();poolRuntimeB=null;await reset(poolB);readyB=await provisionSchemaVersion(dbB,'public');haReadyB=await provisionBpcHaSchema(dbB);await provisionBpcRuntimeMutationBoundary(dbB,'bpc_runtime_acceptance','mutation-v1',mutationTicketSecret);poolRuntimeB=new Pool({connectionString:runtimeUrlB.toString(),max:4});poolRuntimeB.on('error',()=>{});const dbRuntimeB2=new NodePostgresTransactor(poolRuntimeB as never);readyRuntimeB=await assertSchemaReady(dbRuntimeB2,'public');haReadyRuntimeB=await assertBpcHaSchemaReady(dbRuntimeB2);
  await poolB.query('INSERT INTO ha_outbox_fence(stream_id,fence_token) VALUES($1,1)',[SID]);
  await poolB.query('INSERT INTO ha_outbox_receiver_checkpoint(stream_id,source_epoch,sequence) VALUES($1,$2,0)',[SID,E1]);
  receiver=new PgReceiverCheckpoint<BpcPairMutation>(dbB,SID,bpcPairMutationSanitizer,new PgPairMutationApplier(SID,keyring),readyB);
  await importPairSnapshotBundle(dbB,sourceResolver,snapshotAtC,bpcPairMutationSanitizer,new PgPairMutationApplier(SID,keyring));
  assert.equal(Number((await poolB.query('SELECT sequence FROM ha_outbox_receiver_checkpoint WHERE stream_id=$1',[SID])).rows[0].sequence),3);
  const tampered=structuredClone(snapshotAtC);(tampered.records[0] as {opDigest:string}).opDigest='0'.repeat(64);
  await assert.rejects(importPairSnapshotBundle(dbB,sourceResolver,tampered,bpcPairMutationSanitizer,new PgPairMutationApplier(SID,keyring)),/digest|empty pair authority/);
  const grant2=signSourceLeaseGrant('guard-v1',guardPrivate,{streamId:SID,epoch:1,status:'active',holderNodeId:'node-a',leaseId:'lease-a',commandId:'renew-a2',expiresAtMs:aLeaseExpiry,maxTransactionDurationMs:dbA.maxTransactionDurationMs,grantSeq:2,prevDigest:grant1.grantDigest});
  await dbA.transaction((exec)=>installSourceLeaseGrant(exec,sourceResolver,grant2));await dbControl.transaction((exec)=>installSourceLeaseGrant(exec,sourceResolver,grant2));
  const binding2={...binding1,grantDigest:grant2.grantDigest}; storeA=await makeStoreA(binding2);
  await storeA.set(pair(4));await storeA.set(pair(5));await storeA.set(pair(6));

  // Begin a mutation while the lease and quorum are valid, partition this
  // writer from the quorum after DML, then release the callback. The real
  // pre-commit hook must reject and roll back the entire transaction.
  await poolA.query('CREATE TABLE IF NOT EXISTS precommit_probe(id int primary key)');
  await poolA.query('GRANT SELECT,INSERT ON precommit_probe TO bpc_runtime_acceptance');const liveFence=await PgSourceLeaseFence.open(dbRuntimeA,haReadyRuntimeA,sourceResolver,binding2,fenceStore,nodeAIdentity,mutationTicketSigner);
  const guardedOutbox=new PgDurableOutbox(dbRuntimeA,readyRuntimeA,{streamId:SID,sanitizer:bpcPairMutationSanitizer,maxPendingRows:100,backpressure:'fail-authoritative-mutation',preCommitCheck:(exec)=>liveFence.assertWritableInTx(exec),governedAppend:(exec,input)=>liveFence.appendGovernedOutbox(exec,input)});
  let entered!:()=>void,released!:()=>void;const enteredP=new Promise<void>(r=>entered=r),releaseP=new Promise<void>(r=>released=r);
  const inFlight=guardedOutbox.withOutboxTx(async(tx,exec)=>{await guardedOutbox.appendInTx(tx,{streamId:SID,rawMutation:{kind:'bpc.pair.delete.v1',pairId:'precommit-probe'},fenceToken:1n});await exec.query('INSERT INTO precommit_probe(id) VALUES(1)');entered();await releaseP;});
  await enteredP;redisMembers[1]!.disconnect();redisMembers[2]!.disconnect();released();await assert.rejects(inFlight,/majority|deadline|connection|closed|quorum/i);assert.equal(Number((await poolA.query('SELECT count(*)::int n FROM precommit_probe')).rows[0].n),0);await redisMembers[1]!.connect();await redisMembers[2]!.connect();
  const revokedA=signSourceLeaseGrant('guard-v1',guardPrivate,{streamId:SID,epoch:1,status:'revoked',holderNodeId:'node-a',leaseId:'lease-a',commandId:'revoke-a3',expiresAtMs:grant2.expiresAtMs,maxTransactionDurationMs:dbA.maxTransactionDurationMs,grantSeq:3,prevDigest:grant2.grantDigest});
  await dbA.transaction(exec=>installSourceLeaseGrant(exec,sourceResolver,revokedA));await dbControl.transaction(exec=>installSourceLeaseGrant(exec,sourceResolver,revokedA));

  // Live Redis partition: old A can still reach A-PG, but its control-issued
  // lease expires and the in-tx pre-commit gate refuses the write.
  const redisProxy=await startRedisProxy(); const probe=new Redis(redisProxy.url,{connectTimeout:500,maxRetriesPerRequest:0,retryStrategy:()=>null});await probe.ping();probe.disconnect();await redisProxy.partition();
  const cutoverAt=Date.now(); await sleep(Math.max(0,aLeaseExpiry-Date.now()+1_100));
  const bundle=await buildPairSnapshotBundle<BpcPairMutation>(dbA,SID,6,'source-v1',sourcePrivate);
  assert.equal(bundle.manifest.finalSequence,6);
  const tailAtCutover=bundle.manifest.finalSequence-Number((await poolB.query('SELECT sequence FROM ha_outbox_receiver_checkpoint WHERE stream_id=$1',[SID])).rows[0].sequence);assert.equal(tailAtCutover,3);

  const redisB=signRedisFenceRecord('guard-v1',guardPrivate,{streamId:SID,epoch:2,nodeId:'node-b',authoritySystemId:idB,nodeCredentialKeyId:'node-b-hsm',commandId:'promote-b',claimedAtMs:Date.now()});
  const controller=await BpcCutoverController.open(dbControl,haReadyControl,sourceResolver,'guard-v1',guardPrivate,25);
  await controller.begin({streamId:SID,commandId:'promote-b',previousEpoch:1,targetEpoch:2,targetNodeId:'node-b',targetSourceEpoch:E2,manifestDigest:pairSnapshotManifestDigest(bundle.manifest),finalSourceSequence:bundle.manifest.finalSequence,stateDigest:bundle.manifest.stateDigest,redisClaimDigest:redisFenceRecordDigest(redisB),oldLeaseDigest:revokedA.grantDigest,oldLeaseExpiresAtMs:revokedA.expiresAtMs,sourceTransactionWindowMs:binding2.maxTransactionDurationMs});
  assert.equal(await fenceStore.claim(redisB),true);
  const fenced=await controller.markFenced('promote-b',fenceStore);

  await drain(); const resyncMs=Date.now()-cutoverAt;
  assert.equal(Number((await poolB.query('SELECT sequence FROM ha_outbox_receiver_checkpoint WHERE stream_id=$1',[SID])).rows[0].sequence),6);
  const evil=signRedisFenceRecord('guard-v1',guardPrivate,{streamId:SID,epoch:2,nodeId:'evil',authoritySystemId:idA,nodeCredentialKeyId:'node-a-hsm',commandId:'split-brain',claimedAtMs:Date.now()});
  await assert.rejects(fenceStore.claim(evil),/conflicting|disagrees|rollback|future/);
  const grantB=signSourceLeaseGrant('guard-v1',guardPrivate,{streamId:SID,epoch:2,status:'active',holderNodeId:'node-b',leaseId:'lease-b',commandId:'grant-b1',expiresAtMs:Date.now()+60_000,maxTransactionDurationMs:dbB.maxTransactionDurationMs,grantSeq:1,prevDigest:null});
  await dbB.transaction((exec)=>installSourceLeaseGrant(exec,sourceResolver,grantB));
  await promoteReceiverToSource(dbB,sourceResolver,bundle,bpcPairMutationSanitizer,2,E2,sourceResolver,fenced);
  const wrongAuthority=await buildPromotionReadinessAttestation(dbB,fenced,'guard-v1','guard-v1',guardPrivate);await assert.rejects(controller.markActive('promote-b',wrongAuthority,sourceResolver),/independent snapshot authority/);
  const aliasedGuard=await buildPromotionReadinessAttestation(dbB,fenced,'guard-alias','guard-alias',guardPrivate);await assert.rejects(controller.markActive('promote-b',aliasedGuard,sourceResolver),/independent snapshot authority/);
  const readiness=await buildPromotionReadinessAttestation(dbB,fenced,bundle.manifest.keyId,'source-v1',sourcePrivate);const active=await controller.markActive('promote-b',readiness,sourceResolver);await installActiveCutoverReceipt(dbB,sourceResolver,active,readiness);
  const bindingB={streamId:SID,epoch:2,holderNodeId:'node-b',authoritySystemId:idB,nodeCredentialKeyId:'node-b-hsm',leaseId:'lease-b',grantDigest:grantB.grantDigest,redisClaimDigest:redisFenceRecordDigest(redisB),maxClockSkewMs:25,maxTransactionDurationMs:dbB.maxTransactionDurationMs,activationDigest:active.stateDigestSigned};
  const storeB=createHaPairAuthority(dbRuntimeB2,readyRuntimeB,{streamId:SID,fenceToken:2n,keyring,maxPendingRows:100},await PgSourceLeaseFence.open(dbRuntimeB2,haReadyRuntimeB,sourceResolver,bindingB,fenceStore,nodeBIdentity,mutationTicketSigner));
  await assert.rejects(PgSourceLeaseFence.open(dbRuntimeB2,haReadyRuntimeB,sourceResolver,bindingB,fenceStore,nodeAIdentity,mutationTicketSigner),/node identity prover/);
  const cloneBinding={...bindingB,authoritySystemId:idA};await assert.rejects(async()=>{const clonedStore=createHaPairAuthority(dbRuntimeB2,readyRuntimeB,{streamId:SID,fenceToken:2n,keyring,maxPendingRows:100},await PgSourceLeaseFence.open(dbRuntimeB2,haReadyRuntimeB,sourceResolver,cloneBinding,fenceStore,nodeBIdentity,mutationTicketSigner));await clonedStore.set(pair(99));},/PostgreSQL identity|readiness binding/);assert.equal(Number((await poolB.query("SELECT count(*)::int n FROM bpc_pairs WHERE id='pair-99'")).rows[0].n),0);
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
finally { if(server)await new Promise<void>((resolve)=>server!.close(()=>resolve()));await poolRuntimeA?.end().catch(()=>{});await poolRuntimeB?.end().catch(()=>{});await poolA.end().catch(()=>{});await poolB.end().catch(()=>{});await poolControl.end().catch(()=>{});for(const redis of redisMembers)redis.disconnect();sealKey.fill(0);mutationTicketSecret.fill(0);requestSecret.fill(0);responseSecret.fill(0);ackSecret.fill(0); }
