/**
 * BPC #16 final-acceptance primitives: a cross-process Redis epoch fence,
 * guard-signed expiring source leases enforced inside the authoritative
 * PostgreSQL transaction, and signed snapshot/promotion receipts.
 *
 * These primitives deliberately keep control state in `bpc_ha`, separate from
 * the attested pair/outbox schema. The runtime database role must not hold DDL
 * privileges after provisioning.
 */
import { createHash, createPrivateKey, sign as edSign, verify as edVerify, type KeyObject } from 'node:crypto';
import type { Redis } from 'ioredis';

import { ContractValidationError, assertHeaderConformant, canonicalOpDigest, canonicalize, type MutationSanitizer, type OutboxRecord, type SanitizedMutation } from './ha-outbox-contract.js';
import type { PgExecutor, PgTransactor } from './ha-outbox-pg.js';
import type { MutationApplier } from './ha-outbox-pg.js';
import { __internalCreateHaPairStore, type PgTransactionalPairStore, type PgTransactionalPairStoreOptions } from './pg-durable-pair-store.js';
import type { SchemaReadyToken } from './ha-outbox-pg.js';

const STREAM_RE = /^[A-Za-z0-9:._/-]{1,512}$/;
const ID_RE = /^[A-Za-z0-9:._-]{1,128}$/;
const KEY_RE = /^[A-Za-z0-9._-]{1,64}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const B64U = /^[A-Za-z0-9_-]+$/;
const MAX_EPOCH = 2 ** 40;
const MAX_MS = 8.64e15;

function safeInt(value: unknown, label: string, min = 0, max = Number.MAX_SAFE_INTEGER): number {
  const n = typeof value === 'bigint' || typeof value === 'string' ? Number(value) : value;
  if (typeof n !== 'number' || !Number.isSafeInteger(n) || n < min || n > max) {
    throw new ContractValidationError(`${label} must be a safe integer in [${min}, ${max}]`);
  }
  return n;
}
function id(value: unknown, re: RegExp, label: string): string {
  if (typeof value !== 'string' || !re.test(value)) throw new ContractValidationError(`invalid ${label}`);
  return value;
}
function frame(...parts: (string | number | null)[]): Buffer {
  const chunks: Buffer[] = [];
  for (const value of parts) {
    if (value === null) { chunks.push(Buffer.from([0])); continue; }
    const bytes = Buffer.from(String(value), 'utf8');
    const length = Buffer.alloc(4); length.writeUInt32BE(bytes.length);
    chunks.push(Buffer.from([1]), length, bytes);
  }
  return Buffer.concat(chunks);
}
const sha256 = (value: string | Buffer): string => createHash('sha256').update(value).digest('hex');

export interface PublicKeyResolver { resolve(keyId: string): KeyObject | null }
function publicKey(resolver: PublicKeyResolver, keyId: string): KeyObject {
  id(keyId, KEY_RE, 'keyId');
  const key = resolver.resolve(keyId);
  if (!key || key.type !== 'public' || key.asymmetricKeyType !== 'ed25519') {
    throw new ContractValidationError('unknown/revoked keyId or non-public ed25519 verify key');
  }
  return key;
}
function privateKey(key: KeyObject | string): KeyObject {
  const parsed = typeof key === 'string' ? createPrivateKey(key) : key;
  if (parsed.type !== 'private' || parsed.asymmetricKeyType !== 'ed25519') {
    throw new ContractValidationError('signing key must be an ed25519 private key');
  }
  return parsed;
}
function sign(keyId: string, key: KeyObject | string, message: Buffer): string {
  id(keyId, KEY_RE, 'keyId');
  return edSign(null, Buffer.concat([frame('bpc-ha-key/v1', keyId), message]), privateKey(key)).toString('base64url');
}
function verify(resolver: PublicKeyResolver, keyId: string, message: Buffer, signature: string): void {
  if (typeof signature !== 'string' || !B64U.test(signature)) throw new ContractValidationError('invalid signature encoding');
  const ok = edVerify(null, Buffer.concat([frame('bpc-ha-key/v1', keyId), message]), publicKey(resolver, keyId), Buffer.from(signature, 'base64url'));
  if (!ok) throw new ContractValidationError('invalid signature');
}
function publicKeyFingerprint(resolver:PublicKeyResolver,keyId:string):string{return sha256(publicKey(resolver,keyId).export({format:'der',type:'spki'}));}

export const BPC_HA_SCHEMA = `
CREATE SCHEMA IF NOT EXISTS bpc_ha;
CREATE TABLE IF NOT EXISTS bpc_ha.source_lease (
  stream_id text PRIMARY KEY,
  epoch bigint NOT NULL CHECK (epoch BETWEEN 1 AND ${MAX_EPOCH}),
  status text NOT NULL CHECK (status IN ('active','revoked')),
  holder_node_id text NOT NULL,
  lease_id text NOT NULL,
  command_id text NOT NULL,
  expires_at_ms bigint NOT NULL CHECK (expires_at_ms BETWEEN 0 AND ${MAX_MS}),
  grant_seq bigint NOT NULL CHECK (grant_seq BETWEEN 1 AND ${Number.MAX_SAFE_INTEGER}),
  prev_digest text CHECK (prev_digest IS NULL OR prev_digest ~ '^[0-9a-f]{64}$'),
  grant_digest text NOT NULL CHECK (grant_digest ~ '^[0-9a-f]{64}$'),
  key_id text NOT NULL,
  signature text NOT NULL
);
CREATE TABLE IF NOT EXISTS bpc_ha.source_lease_history (
  LIKE bpc_ha.source_lease INCLUDING DEFAULTS INCLUDING CONSTRAINTS,
  PRIMARY KEY (stream_id, grant_seq),
  UNIQUE (stream_id, grant_digest),
  UNIQUE (stream_id, command_id)
);
CREATE TABLE IF NOT EXISTS bpc_ha.promotion_receipt (
  stream_id text NOT NULL,
  target_epoch bigint NOT NULL CHECK (target_epoch BETWEEN 1 AND ${MAX_EPOCH}),
  source_manifest_digest text NOT NULL CHECK (source_manifest_digest ~ '^[0-9a-f]{64}$'),
  final_source_sequence bigint NOT NULL CHECK (final_source_sequence BETWEEN 0 AND ${Number.MAX_SAFE_INTEGER}),
  state_digest text NOT NULL CHECK (state_digest ~ '^[0-9a-f]{64}$'),
  source_key_id text NOT NULL,
  source_signature text NOT NULL,
  guard_key_id text NOT NULL,
  guard_signature text NOT NULL,
  promoted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (stream_id, target_epoch)
);
CREATE TABLE IF NOT EXISTS bpc_ha.epoch_witness (
  stream_id text PRIMARY KEY,
  epoch bigint NOT NULL CHECK (epoch BETWEEN 0 AND ${MAX_EPOCH}),
  state_digest text NOT NULL CHECK (state_digest ~ '^[0-9a-f]{64}$')
);
CREATE TABLE IF NOT EXISTS bpc_ha.cutover_head (
  stream_id text PRIMARY KEY,
  command_id text NOT NULL UNIQUE,
  phase text NOT NULL CHECK (phase IN ('PREPARING','FENCED','ACTIVE')),
  previous_epoch bigint NOT NULL CHECK (previous_epoch BETWEEN 0 AND ${MAX_EPOCH - 1}),
  target_epoch bigint NOT NULL CHECK (target_epoch BETWEEN 1 AND ${MAX_EPOCH}),
  target_node_id text NOT NULL,
  target_source_epoch text NOT NULL,
  manifest_digest text NOT NULL CHECK (manifest_digest ~ '^[0-9a-f]{64}$'),
  final_source_sequence bigint NOT NULL CHECK (final_source_sequence BETWEEN 0 AND ${Number.MAX_SAFE_INTEGER}),
  state_digest text NOT NULL CHECK (state_digest ~ '^[0-9a-f]{64}$'),
  redis_claim_digest text NOT NULL CHECK (redis_claim_digest ~ '^[0-9a-f]{64}$'),
  old_lease_digest text NOT NULL CHECK (old_lease_digest ~ '^[0-9a-f]{64}$'),
  old_lease_expires_at_ms bigint NOT NULL CHECK (old_lease_expires_at_ms BETWEEN 0 AND ${MAX_MS}),
  source_transaction_window_ms bigint NOT NULL CHECK (source_transaction_window_ms BETWEEN 1 AND 300000),
  prev_state_digest text,
  state_digest_signed text NOT NULL CHECK (state_digest_signed ~ '^[0-9a-f]{64}$'),
  key_id text NOT NULL,
  signature text NOT NULL
);
CREATE TABLE IF NOT EXISTS bpc_ha.cutover_history (
  LIKE bpc_ha.cutover_head INCLUDING DEFAULTS INCLUDING CONSTRAINTS,
  PRIMARY KEY(stream_id,target_epoch,phase),
  UNIQUE(stream_id,state_digest_signed)
);
CREATE TABLE IF NOT EXISTS bpc_ha.source_activation (
  stream_id text PRIMARY KEY,
  epoch bigint NOT NULL CHECK (epoch BETWEEN 2 AND ${MAX_EPOCH}),
  state_digest_signed text NOT NULL CHECK (state_digest_signed ~ '^[0-9a-f]{64}$'),
  key_id text NOT NULL,
  signature text NOT NULL,
  receipt jsonb NOT NULL,
  readiness jsonb NOT NULL
);
CREATE TABLE IF NOT EXISTS bpc_ha.promotion_attestation (
  command_id text PRIMARY KEY,
  attestation_digest text NOT NULL CHECK (attestation_digest ~ '^[0-9a-f]{64}$'),
  key_id text NOT NULL,
  signature text NOT NULL,
  payload jsonb NOT NULL
);
CREATE TABLE IF NOT EXISTS bpc_ha.authority_stream (
  stream_id text PRIMARY KEY
);
CREATE TABLE IF NOT EXISTS bpc_ha.redis_membership (
  id smallint PRIMARY KEY CHECK(id=1),
  membership_digest text NOT NULL CHECK(membership_digest ~ '^[0-9a-f]{64}$')
);
CREATE TABLE IF NOT EXISTS bpc_ha.schema_meta (
  id smallint PRIMARY KEY CHECK(id=1),
  version integer NOT NULL CHECK(version=1),
  manifest_digest text NOT NULL CHECK(manifest_digest ~ '^[0-9a-f]{64}$')
)
`.trim();

export const BPC_HA_SCHEMA_VERSION=1;
export const BPC_HA_SCHEMA_MANIFEST='d467c28dd1fc0be804cfd5f91b60ee3e65d2aeedd1cd631a8e867c7dad2f1c09';
const HA_READY_STATE=new WeakMap<object,{db:PgTransactor;manifest:string}>();
export interface BpcHaReadyToken{readonly __bpcHaReady:never}
export async function bpcHaSchemaManifest(exec:PgExecutor):Promise<string>{
  const relations=(await exec.query(`SELECT c.relname,c.relkind,c.relpersistence,c.relrowsecurity,c.relforcerowsecurity FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='bpc_ha' AND c.relkind IN ('r','p','v','m') ORDER BY c.relname`)).rows;
  const columns=(await exec.query(`SELECT c.relname,a.attnum,a.attname,pg_catalog.format_type(a.atttypid,a.atttypmod) type,a.attnotnull,pg_catalog.pg_get_expr(d.adbin,d.adrelid) default_expr FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace JOIN pg_catalog.pg_attribute a ON a.attrelid=c.oid LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid=c.oid AND d.adnum=a.attnum WHERE n.nspname='bpc_ha' AND c.relkind IN ('r','p') AND a.attnum>0 AND NOT a.attisdropped ORDER BY c.relname,a.attnum`)).rows;
  const constraints=(await exec.query(`SELECT c.relname,k.conname,k.contype,pg_catalog.pg_get_constraintdef(k.oid,true) definition FROM pg_catalog.pg_constraint k JOIN pg_catalog.pg_class c ON c.oid=k.conrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='bpc_ha' ORDER BY c.relname,k.conname`)).rows;
  const indexes=(await exec.query(`SELECT t.relname table_name,i.relname index_name,pg_catalog.pg_get_indexdef(i.oid) definition FROM pg_catalog.pg_index x JOIN pg_catalog.pg_class t ON t.oid=x.indrelid JOIN pg_catalog.pg_class i ON i.oid=x.indexrelid JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace WHERE n.nspname='bpc_ha' ORDER BY t.relname,i.relname`)).rows;
  const triggers=(await exec.query(`SELECT c.relname,t.tgname,t.tgenabled,pg_catalog.pg_get_triggerdef(t.oid,true) definition FROM pg_catalog.pg_trigger t JOIN pg_catalog.pg_class c ON c.oid=t.tgrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='bpc_ha' AND NOT t.tgisinternal ORDER BY c.relname,t.tgname`)).rows;
  const policies=(await exec.query(`SELECT schemaname,tablename,policyname,permissive,roles,cmd,qual,with_check FROM pg_catalog.pg_policies WHERE schemaname='bpc_ha' ORDER BY tablename,policyname`)).rows;
  return sha256(canonicalize({relations,columns,constraints,indexes,triggers,policies}));
}
export async function provisionBpcHaSchema(db:PgTransactor):Promise<BpcHaReadyToken>{const manifest=await db.transaction(async exec=>{const found=await bpcHaSchemaManifest(exec);if(found!==BPC_HA_SCHEMA_MANIFEST)throw new ContractValidationError(`bpc_ha schema attestation failed (${found})`);const inserted=await exec.query('INSERT INTO bpc_ha.schema_meta(id,version,manifest_digest) VALUES(1,$1,$2) ON CONFLICT(id) DO NOTHING',[BPC_HA_SCHEMA_VERSION,found]);if(inserted.rowCount===0){const row=(await exec.query('SELECT version,manifest_digest FROM bpc_ha.schema_meta WHERE id=1 FOR SHARE')).rows[0];if(!row||safeInt(row.version,'bpc_ha schema version',1,1)!==1||String(row.manifest_digest)!==found)throw new ContractValidationError('bpc_ha schema authority conflicts');}return found;});const token={} as BpcHaReadyToken;HA_READY_STATE.set(token,{db,manifest});return token;}
async function requireBpcHaReady(token:BpcHaReadyToken,db:PgTransactor):Promise<void>{const state=HA_READY_STATE.get(token as object);if(!state||state.db!==db||state.manifest!==BPC_HA_SCHEMA_MANIFEST)throw new ContractValidationError('invalid bpc_ha schema-readiness capability');await db.transaction(async exec=>{const found=await bpcHaSchemaManifest(exec);const row=(await exec.query('SELECT version,manifest_digest FROM bpc_ha.schema_meta WHERE id=1 FOR SHARE')).rows[0];if(found!==BPC_HA_SCHEMA_MANIFEST||!row||safeInt(row.version,'bpc_ha schema version',1,1)!==1||String(row.manifest_digest)!==found)throw new ContractValidationError('bpc_ha schema attestation failed');});}

export interface SourceLeaseGrant {
  streamId: string; epoch: number; status: 'active' | 'revoked'; holderNodeId: string;
  leaseId: string; commandId: string; expiresAtMs: number; grantSeq: number;
  prevDigest: string | null; grantDigest: string; keyId: string; signature: string;
}
export type BareSourceLeaseGrant = Omit<SourceLeaseGrant, 'grantDigest' | 'keyId' | 'signature'>;
function leaseMessage(value: BareSourceLeaseGrant, digest: string): Buffer {
  return frame('bpc-source-lease/v1', value.streamId, value.epoch, value.status, value.holderNodeId,
    value.leaseId, value.commandId, value.expiresAtMs, value.grantSeq, value.prevDigest, digest);
}
function validateBareLease(value: BareSourceLeaseGrant): void {
  id(value.streamId, STREAM_RE, 'streamId'); id(value.holderNodeId, ID_RE, 'holderNodeId');
  id(value.leaseId, ID_RE, 'leaseId'); id(value.commandId, ID_RE, 'commandId');
  safeInt(value.epoch, 'epoch', 1, MAX_EPOCH); safeInt(value.expiresAtMs, 'expiresAtMs', 0, MAX_MS);
  safeInt(value.grantSeq, 'grantSeq', 1);
  if (value.status !== 'active' && value.status !== 'revoked') throw new ContractValidationError('invalid lease status');
  if (value.prevDigest !== null && !HEX64.test(value.prevDigest)) throw new ContractValidationError('invalid prevDigest');
}
export function signSourceLeaseGrant(keyId: string, key: KeyObject | string, bare: BareSourceLeaseGrant): SourceLeaseGrant {
  validateBareLease(bare);
  const grantDigest = sha256(leaseMessage(bare, ''));
  return { ...bare, grantDigest, keyId, signature: sign(keyId, key, leaseMessage(bare, grantDigest)) };
}
export function verifySourceLeaseGrant(resolver: PublicKeyResolver, value: SourceLeaseGrant): void {
  validateBareLease(value);
  if (!HEX64.test(value.grantDigest) || sha256(leaseMessage(value, '')) !== value.grantDigest) {
    throw new ContractValidationError('lease grant digest mismatch');
  }
  verify(resolver, value.keyId, leaseMessage(value, value.grantDigest), value.signature);
}

function leaseFromRow(row: Record<string, unknown>): SourceLeaseGrant {
  return {
    streamId: String(row.stream_id), epoch: safeInt(row.epoch, 'epoch', 1, MAX_EPOCH),
    status: String(row.status) as SourceLeaseGrant['status'], holderNodeId: String(row.holder_node_id),
    leaseId: String(row.lease_id), commandId: String(row.command_id),
    expiresAtMs: safeInt(row.expires_at_ms, 'expiresAtMs', 0, MAX_MS),
    grantSeq: safeInt(row.grant_seq, 'grantSeq', 1), prevDigest: row.prev_digest === null ? null : String(row.prev_digest),
    grantDigest: String(row.grant_digest), keyId: String(row.key_id), signature: String(row.signature),
  };
}
const LEASE_COLS = 'stream_id,epoch,status,holder_node_id,lease_id,command_id,expires_at_ms,grant_seq,prev_digest,grant_digest,key_id,signature';
const leaseValues = (g: SourceLeaseGrant): unknown[] => [g.streamId,g.epoch,g.status,g.holderNodeId,g.leaseId,g.commandId,g.expiresAtMs,g.grantSeq,g.prevDigest,g.grantDigest,g.keyId,g.signature];

export async function installSourceLeaseGrant(exec: PgExecutor, resolver: PublicKeyResolver, grant: SourceLeaseGrant): Promise<void> {
  verifySourceLeaseGrant(resolver, grant);
  await exec.query('SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1,0))', [grant.streamId]);
  const currentRow = (await exec.query(`SELECT ${LEASE_COLS} FROM bpc_ha.source_lease WHERE stream_id=$1 FOR UPDATE`, [grant.streamId])).rows[0];
  const current = currentRow ? leaseFromRow(currentRow) : null;
  if (current) verifySourceLeaseGrant(resolver, current);
  const byCommand = (await exec.query('SELECT grant_digest FROM bpc_ha.source_lease_history WHERE stream_id=$1 AND command_id=$2', [grant.streamId, grant.commandId])).rows[0];
  if (byCommand) {
    if (String(byCommand.grant_digest) !== grant.grantDigest) throw new ContractValidationError('lease command reused with different grant');
    return;
  }
  if (grant.grantSeq !== (current?.grantSeq ?? 0) + 1 || grant.prevDigest !== (current?.grantDigest ?? null)) {
    throw new ContractValidationError('lease grant does not advance the signed chain');
  }
  if (current && grant.epoch < current.epoch) throw new ContractValidationError('lease epoch regression');
  const first = (await exec.query('SELECT holder_node_id,lease_id,status FROM bpc_ha.source_lease_history WHERE stream_id=$1 AND epoch=$2 ORDER BY grant_seq LIMIT 1', [grant.streamId, grant.epoch])).rows[0];
  if (first && (String(first.holder_node_id) !== grant.holderNodeId || String(first.lease_id) !== grant.leaseId)) {
    throw new ContractValidationError('holder/lease identity cannot pivot within an epoch');
  }
  const revoked = (await exec.query("SELECT 1 FROM bpc_ha.source_lease_history WHERE stream_id=$1 AND epoch=$2 AND status='revoked' LIMIT 1", [grant.streamId, grant.epoch])).rows[0];
  if (revoked && grant.status === 'active') throw new ContractValidationError('revoked epoch cannot reactivate');
  const priorMax=(await exec.query('SELECT max(expires_at_ms)::text value FROM bpc_ha.source_lease_history WHERE stream_id=$1 AND epoch=$2',[grant.streamId,grant.epoch])).rows[0]?.value;
  if(priorMax!==null&&priorMax!==undefined&&grant.expiresAtMs<safeInt(priorMax,'prior maximum expiry',0,MAX_MS))throw new ContractValidationError('lease expiry cannot decrease within an epoch');
  const values = leaseValues(grant);
  const inserted = await exec.query(`INSERT INTO bpc_ha.source_lease_history (${LEASE_COLS}) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, values);
  if (inserted.rowCount !== 1) throw new ContractValidationError('lease history insert failed');
  if (!current) {
    const head = await exec.query(`INSERT INTO bpc_ha.source_lease (${LEASE_COLS}) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, values);
    if (head.rowCount !== 1) throw new ContractValidationError('lease head insert failed');
  } else {
    const head = await exec.query(`UPDATE bpc_ha.source_lease SET epoch=$2,status=$3,holder_node_id=$4,lease_id=$5,command_id=$6,expires_at_ms=$7,grant_seq=$8,prev_digest=$9,grant_digest=$10,key_id=$11,signature=$12 WHERE stream_id=$1 AND grant_digest=$13`, [...values, current.grantDigest]);
    if (head.rowCount !== 1) throw new ContractValidationError('lease head forward-CAS failed');
  }
}

export interface SourceLeaseBinding { streamId: string; epoch: number; holderNodeId: string; authoritySystemId:string; leaseId: string; grantDigest: string; redisClaimDigest:string; maxClockSkewMs: number; maxTransactionDurationMs:number; activationDigest?:string }
const FENCE_CAPABILITIES = new WeakMap<PgSourceLeaseFence, PgTransactor>();
export class PgSourceLeaseFence {
  private constructor(private readonly db: PgTransactor, private readonly resolver: PublicKeyResolver, private readonly binding: SourceLeaseBinding,private readonly quorum:BpcRedisQuorumFenceStore) {
    id(binding.streamId, STREAM_RE, 'streamId'); id(binding.holderNodeId, ID_RE, 'holderNodeId'); id(binding.leaseId, ID_RE, 'leaseId');
    if(!/^\d+$/.test(binding.authoritySystemId))throw new ContractValidationError('invalid authoritySystemId');
    safeInt(binding.epoch, 'epoch', 1, MAX_EPOCH); safeInt(binding.maxClockSkewMs, 'maxClockSkewMs', 0, 60_000);safeInt(binding.maxTransactionDurationMs,'maxTransactionDurationMs',1,300_000);if(db.maxTransactionDurationMs!==binding.maxTransactionDurationMs)throw new ContractValidationError('source transaction window is not bound to the configured PgTransactor');
    if (!HEX64.test(binding.grantDigest)) throw new ContractValidationError('invalid grantDigest');
    if (!HEX64.test(binding.redisClaimDigest)) throw new ContractValidationError('invalid redisClaimDigest');
    if(binding.epoch>1&&(!binding.activationDigest||!HEX64.test(binding.activationDigest)))throw new ContractValidationError('promoted source requires a signed ACTIVE cutover digest');
  }
  static async open(db: PgTransactor, ready:BpcHaReadyToken,resolver: PublicKeyResolver, binding: SourceLeaseBinding,quorum:BpcRedisQuorumFenceStore): Promise<PgSourceLeaseFence> {
    await requireBpcHaReady(ready,db);
    const fence = new PgSourceLeaseFence(db, resolver, binding,quorum);
    await db.transaction(async(exec) => {await fence.assertWritableInTx(exec);await exec.query('INSERT INTO bpc_ha.authority_stream(stream_id) VALUES($1) ON CONFLICT DO NOTHING',[binding.streamId]);});
    FENCE_CAPABILITIES.set(fence, db);
    return fence;
  }
  async assertWritableInTx(exec: PgExecutor): Promise<void> {
    const row = (await exec.query(`SELECT ${LEASE_COLS},(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint::text AS db_now_ms FROM bpc_ha.source_lease WHERE stream_id=$1 FOR SHARE`, [this.binding.streamId])).rows[0];
    if (!row) throw new ContractValidationError('source lease missing (fail closed)');
    const lease = leaseFromRow(row); verifySourceLeaseGrant(this.resolver, lease);
    const latest = (await exec.query('SELECT grant_seq,grant_digest FROM bpc_ha.source_lease_history WHERE stream_id=$1 ORDER BY grant_seq DESC LIMIT 1', [this.binding.streamId])).rows[0];
    if (!latest || safeInt(latest.grant_seq, 'latest grantSeq', 1) !== lease.grantSeq || String(latest.grant_digest) !== lease.grantDigest) {
      throw new ContractValidationError('source lease head/history mismatch');
    }
    if (lease.status !== 'active' || lease.epoch !== this.binding.epoch || lease.holderNodeId !== this.binding.holderNodeId || lease.leaseId !== this.binding.leaseId || lease.grantDigest !== this.binding.grantDigest) {
      throw new ContractValidationError('source lease binding is stale or revoked');
    }
    const dbNow = safeInt(row.db_now_ms, 'database clock', 0, MAX_MS);
    if (dbNow + this.binding.maxClockSkewMs >= lease.expiresAtMs) throw new ContractValidationError('source lease expired (fail closed)');
    if(this.binding.epoch>1){const active=(await exec.query('SELECT state_digest_signed,receipt,readiness FROM bpc_ha.source_activation WHERE stream_id=$1 AND epoch=$2',[this.binding.streamId,this.binding.epoch])).rows[0];if(!active||String(active.state_digest_signed)!==this.binding.activationDigest)throw new ContractValidationError('promoted source ACTIVE receipt missing or stale');const receipt=active.receipt as CutoverReceipt,readiness=active.readiness as PromotionReadinessAttestation;verifyCutoverReceipt(this.resolver,receipt);verifyPromotionReadinessAttestation(this.resolver,readiness);if(receipt.phase!=='ACTIVE'||receipt.streamId!==this.binding.streamId||receipt.targetEpoch!==this.binding.epoch||receipt.stateDigestSigned!==this.binding.activationDigest||readiness.fencedDigest!==receipt.prevStateDigest||readiness.targetSystemId!==this.binding.authoritySystemId)throw new ContractValidationError('promoted source ACTIVE/readiness binding invalid');}
    const redis=await this.quorum.current();if(redis.streamId!==this.binding.streamId||redis.epoch!==this.binding.epoch||redis.nodeId!==this.binding.holderNodeId||redisFenceRecordDigest(redis)!==this.binding.redisClaimDigest)throw new ContractValidationError('external Redis fence authority is missing, stale, or conflicting');
    const systemId=String((await exec.query('SELECT system_identifier::text value FROM pg_catalog.pg_control_system()')).rows[0]?.value);if(systemId!==this.binding.authoritySystemId||redis.authoritySystemId!==systemId)throw new ContractValidationError('source authority PostgreSQL identity does not match its signed fence');
  }
}

/** The only public HA pair-authority constructor. The source lease capability
 * is bound to the exact transactor used by the pair authority. */
export function createHaPairAuthority(db: PgTransactor, ready: SchemaReadyToken, opts: PgTransactionalPairStoreOptions, fence: PgSourceLeaseFence): PgTransactionalPairStore {
  if (FENCE_CAPABILITIES.get(fence) !== db) throw new ContractValidationError('source fence is not bound to this PostgreSQL authority');
  return __internalCreateHaPairStore(db, ready, opts, (exec) => fence.assertWritableInTx(exec));
}

export interface RedisFenceRecord { streamId: string; epoch: number; nodeId: string; authoritySystemId:string; commandId: string; claimedAtMs: number; keyId: string; signature: string }
type BareRedisFenceRecord = Omit<RedisFenceRecord, 'keyId' | 'signature'>;
function redisFenceMessage(value: BareRedisFenceRecord): Buffer {
  return frame('bpc-redis-fence/v1', value.streamId, value.epoch, value.nodeId,value.authoritySystemId, value.commandId, value.claimedAtMs);
}
export function signRedisFenceRecord(keyId: string, key: KeyObject | string, bare: BareRedisFenceRecord): RedisFenceRecord {
  id(bare.streamId, STREAM_RE, 'streamId'); id(bare.nodeId, ID_RE, 'nodeId'); id(bare.commandId, ID_RE, 'commandId');if(!/^\d+$/.test(bare.authoritySystemId))throw new ContractValidationError('invalid authoritySystemId');
  safeInt(bare.epoch, 'epoch', 1, MAX_EPOCH); safeInt(bare.claimedAtMs, 'claimedAtMs', 0, MAX_MS);
  return { ...bare, keyId, signature: sign(keyId, key, redisFenceMessage(bare)) };
}
const CLAIM_FENCE = `
local raw=redis.call('GET',KEYS[1])
if raw then
  local ok,cur=pcall(cjson.decode,raw)
  if not ok or type(cur)~='table' or type(cur.epoch)~='number' then return redis.error_reply('BPC_FENCE_CORRUPT') end
  if cur.epoch>tonumber(ARGV[1]) then return 0 end
  if cur.epoch==tonumber(ARGV[1]) then
    if raw==ARGV[2] then return 1 end
    return 0
  end
end
redis.call('SET',KEYS[1],ARGV[2])
return 1`;
export class BpcRedisFenceStore {
  constructor(private readonly redis: Redis, private readonly resolver: PublicKeyResolver, private readonly key = 'bpc:ha:fence') {
    if (!key || key.length > 512) throw new ContractValidationError('invalid Redis fence key');
  }
  private parse(raw: string): RedisFenceRecord {
    let value: unknown; try { value = JSON.parse(raw); } catch { throw new ContractValidationError('BPC_FENCE_CORRUPT'); }
    if (!value || typeof value !== 'object') throw new ContractValidationError('BPC_FENCE_CORRUPT');
    const v = value as Partial<RedisFenceRecord>;
    id(v.streamId, STREAM_RE, 'streamId'); id(v.nodeId, ID_RE, 'nodeId'); id(v.commandId, ID_RE, 'commandId');if(!/^\d+$/.test(String(v.authoritySystemId)))throw new ContractValidationError('invalid authoritySystemId');
    safeInt(v.epoch, 'epoch', 1, MAX_EPOCH); safeInt(v.claimedAtMs, 'claimedAtMs', 0, MAX_MS);
    verify(this.resolver, String(v.keyId), redisFenceMessage(v as BareRedisFenceRecord), String(v.signature));
    return v as RedisFenceRecord;
  }
  async current(): Promise<RedisFenceRecord | null> { const raw = await this.redis.get(this.key); return raw === null ? null : this.parse(raw); }
  async claim(record: RedisFenceRecord): Promise<boolean> {
    this.parse(JSON.stringify(record));
    return await this.redis.eval(CLAIM_FENCE, 1, this.key, String(record.epoch), JSON.stringify(record)) === 1;
  }
}
const REDIS_WITNESS_CAPABILITIES=new WeakSet<PgRedisFenceWitness>();
const CONTROL_REDIS_READ=Symbol('bpc.control.redis.read');

/** Majority fence across independent Redis authorities. Every member is
 * required to use synchronous AOF before it can join the production claim
 * path. Intersecting majorities prevent conflicting equal-epoch winners. */
export class BpcRedisQuorumFenceStore {
  private constructor(private readonly members: BpcRedisFenceStore[],private readonly witness:PgRedisFenceWitness,private readonly timeoutMs:number) {}
  static async open(clients: Redis[], resolver: PublicKeyResolver,witness:PgRedisFenceWitness, key = 'bpc:ha:fence'): Promise<BpcRedisQuorumFenceStore> {
    if(!REDIS_WITNESS_CAPABILITIES.has(witness))throw new ContractValidationError('Redis fence witness is not an attested control-DB capability');
    if (clients.length < 3 || clients.length % 2 === 0) throw new ContractValidationError('Redis fence quorum requires an odd membership of at least 3');
    const ids=new Set<string>();const bounded=<T>(p:Promise<T>)=>Promise.race([p,new Promise<T>((_,reject)=>{const t=setTimeout(()=>reject(new ContractValidationError('Redis membership inspection deadline exceeded')),2_000);t.unref();p.finally(()=>clearTimeout(t)).catch(()=>{});})]);
    for (const client of clients) {
      const info=await bounded(client.info('server'));const runId=/^run_id:([^\r\n]+)$/m.exec(info)?.[1];const role=String(await bounded(client.role())).toLowerCase();if(!runId||ids.has(runId)||!role.startsWith('master'))throw new ContractValidationError('Redis fence quorum members must be distinct writable server identities');ids.add(runId);
      const aof = await bounded(client.config('GET', 'appendonly'));
      const fsync = await bounded(client.config('GET', 'appendfsync'));
      const last = (raw: unknown): string => Array.isArray(raw) ? String(raw.at(-1)).toLowerCase() : '';
      if (last(aof) !== 'yes' || last(fsync) !== 'always') throw new ContractValidationError('Redis fence member requires appendonly=yes and appendfsync=always');
    }
    await witness.pinMembership([...ids].sort());return new BpcRedisQuorumFenceStore(clients.map((client) => new BpcRedisFenceStore(client, resolver, key)),witness,2_000);
  }
  private quorum(): number { return Math.floor(this.members.length / 2) + 1; }
  private bounded<T>(work:Promise<T>):Promise<T>{return Promise.race([work,new Promise<T>((_,reject)=>{const timer=setTimeout(()=>reject(new ContractValidationError('Redis fence member deadline exceeded')),this.timeoutMs);timer.unref();work.finally(()=>clearTimeout(timer)).catch(()=>{});})]);}
  async claim(record: RedisFenceRecord): Promise<boolean> {
    await this.witness.verify(record);
    const results = await Promise.allSettled(this.members.map((member) => this.bounded(member.claim(record))));
    return results.filter((result) => result.status === 'fulfilled' && result.value).length >= this.quorum();
  }
  private async rawCurrent():Promise<RedisFenceRecord>{
    const results = await Promise.allSettled(this.members.map((member) => this.bounded(member.current())));
    const groups = new Map<string, { record: RedisFenceRecord; count: number }>();
    for (const result of results) if (result.status === 'fulfilled' && result.value) {
      const key = canonicalize(result.value), group = groups.get(key);
      groups.set(key, { record: result.value, count: (group?.count ?? 0) + 1 });
    }
    const winner = [...groups.values()].find((group) => group.count >= this.quorum());
    if (!winner) throw new ContractValidationError('Redis fence quorum has no authoritative majority (fail closed)');
    return winner.record;
  }
  async current():Promise<RedisFenceRecord>{const record=await this.rawCurrent();await this.witness.verify(record);return record;}
  async currentForControl(token:symbol):Promise<RedisFenceRecord>{if(token!==CONTROL_REDIS_READ)throw new ContractValidationError('control Redis read capability invalid');return this.rawCurrent();}
}

export type CutoverPhase = 'PREPARING' | 'FENCED' | 'ACTIVE';
export interface PromotionReadinessAttestation{streamId:string;commandId:string;targetEpoch:number;targetSourceEpoch:string;targetSystemId:string;snapshotKeyId:string;manifestDigest:string;appliedSequence:number;stateDigest:string;fencedDigest:string;keyId:string;attestationDigest:string;signature:string}
type BarePromotionAttestation=Omit<PromotionReadinessAttestation,'keyId'|'attestationDigest'|'signature'>;
const promotionAttestationMessage=(v:BarePromotionAttestation,d:string)=>frame('bpc-promotion-readiness/v1',v.streamId,v.commandId,v.targetEpoch,v.targetSourceEpoch,v.targetSystemId,v.snapshotKeyId,v.manifestDigest,v.appliedSequence,v.stateDigest,v.fencedDigest,d);
export function verifyPromotionReadinessAttestation(resolver:PublicKeyResolver,v:PromotionReadinessAttestation):void{id(v.streamId,STREAM_RE,'streamId');id(v.commandId,ID_RE,'commandId');id(v.targetSourceEpoch,ID_RE,'targetSourceEpoch');id(v.snapshotKeyId,KEY_RE,'snapshotKeyId');if(!/^\d+$/.test(v.targetSystemId))throw new ContractValidationError('promotion target system identity malformed');safeInt(v.targetEpoch,'targetEpoch',1,MAX_EPOCH);safeInt(v.appliedSequence,'appliedSequence');for(const x of [v.manifestDigest,v.stateDigest,v.fencedDigest,v.attestationDigest])if(!HEX64.test(x))throw new ContractValidationError('promotion attestation digest malformed');if(sha256(promotionAttestationMessage(v,''))!==v.attestationDigest)throw new ContractValidationError('promotion attestation digest mismatch');verify(resolver,v.keyId,promotionAttestationMessage(v,v.attestationDigest),v.signature);}
export async function buildPromotionReadinessAttestation(db:PgTransactor,fenced:CutoverReceipt,snapshotKeyId:string,keyId:string,key:KeyObject|string):Promise<PromotionReadinessAttestation>{if(fenced.phase!=='FENCED')throw new ContractValidationError('readiness attestation requires FENCED cutover');return db.transaction(async exec=>{const cp=(await exec.query('SELECT source_epoch,sequence FROM ha_outbox_receiver_checkpoint WHERE stream_id=$1',[fenced.streamId])).rows[0];const source=(await exec.query('SELECT source_epoch,sequence FROM ha_outbox_source_checkpoint WHERE stream_id=$1',[fenced.streamId])).rows[0];if(!cp||safeInt(cp.sequence,'appliedSequence')!==fenced.finalSourceSequence||!source||String(source.source_epoch)!==fenced.targetSourceEpoch||safeInt(source.sequence,'newSourceSequence')!==0||await stateDigest(exec)!==fenced.stateDigest)throw new ContractValidationError('promoted receiver/source state is not ready');const targetSystemId=String((await exec.query('SELECT system_identifier::text value FROM pg_catalog.pg_control_system()')).rows[0]?.value);const bare:BarePromotionAttestation={streamId:fenced.streamId,commandId:fenced.commandId,targetEpoch:fenced.targetEpoch,targetSourceEpoch:fenced.targetSourceEpoch,targetSystemId,snapshotKeyId,manifestDigest:fenced.manifestDigest,appliedSequence:fenced.finalSourceSequence,stateDigest:fenced.stateDigest,fencedDigest:fenced.stateDigestSigned};const attestationDigest=sha256(promotionAttestationMessage(bare,''));return{...bare,keyId,attestationDigest,signature:sign(keyId,key,promotionAttestationMessage(bare,attestationDigest))};});}
export interface CutoverReceipt {
  streamId:string; commandId:string; phase:CutoverPhase; previousEpoch:number; targetEpoch:number;
  targetNodeId:string; targetSourceEpoch:string; manifestDigest:string; finalSourceSequence:number;
  stateDigest:string; redisClaimDigest:string; oldLeaseDigest:string; oldLeaseExpiresAtMs:number;sourceTransactionWindowMs:number;
  prevStateDigest:string|null; stateDigestSigned:string; keyId:string; signature:string;
}
type BareCutover = Omit<CutoverReceipt,'stateDigestSigned'|'keyId'|'signature'>;
const cutoverMessage=(v:BareCutover,digest:string):Buffer=>frame('bpc-cutover/v1',v.streamId,v.commandId,v.phase,v.previousEpoch,v.targetEpoch,v.targetNodeId,v.targetSourceEpoch,v.manifestDigest,v.finalSourceSequence,v.stateDigest,v.redisClaimDigest,v.oldLeaseDigest,v.oldLeaseExpiresAtMs,v.sourceTransactionWindowMs,v.prevStateDigest,digest);
function validateBareCutover(v:BareCutover):void{
  id(v.streamId,STREAM_RE,'streamId');id(v.commandId,ID_RE,'commandId');id(v.targetNodeId,ID_RE,'targetNodeId');id(v.targetSourceEpoch,ID_RE,'targetSourceEpoch');
  if(!['PREPARING','FENCED','ACTIVE'].includes(v.phase))throw new ContractValidationError('invalid cutover phase');
  safeInt(v.previousEpoch,'previousEpoch',0,MAX_EPOCH-1);safeInt(v.targetEpoch,'targetEpoch',1,MAX_EPOCH);safeInt(v.finalSourceSequence,'finalSourceSequence');safeInt(v.oldLeaseExpiresAtMs,'oldLeaseExpiresAtMs',0,MAX_MS);safeInt(v.sourceTransactionWindowMs,'sourceTransactionWindowMs',1,300_000);
  if(v.targetEpoch!==v.previousEpoch+1)throw new ContractValidationError('cutover epoch must advance exactly once');
  for(const [name,value] of Object.entries({manifestDigest:v.manifestDigest,stateDigest:v.stateDigest,redisClaimDigest:v.redisClaimDigest,oldLeaseDigest:v.oldLeaseDigest}))if(!HEX64.test(value))throw new ContractValidationError(`invalid ${name}`);
  if(v.prevStateDigest!==null&&!HEX64.test(v.prevStateDigest))throw new ContractValidationError('invalid previous cutover digest');
}
export function signCutoverReceipt(keyId:string,key:KeyObject|string,bare:BareCutover):CutoverReceipt{validateBareCutover(bare);const stateDigestSigned=sha256(cutoverMessage(bare,''));return{...bare,stateDigestSigned,keyId,signature:sign(keyId,key,cutoverMessage(bare,stateDigestSigned))};}
export function verifyCutoverReceipt(resolver:PublicKeyResolver,value:CutoverReceipt):void{validateBareCutover(value);if(!HEX64.test(value.stateDigestSigned)||sha256(cutoverMessage(value,''))!==value.stateDigestSigned)throw new ContractValidationError('cutover state digest mismatch');verify(resolver,value.keyId,cutoverMessage(value,value.stateDigestSigned),value.signature);}
export async function installActiveCutoverReceipt(db:PgTransactor,resolver:PublicKeyResolver,value:CutoverReceipt,readiness:PromotionReadinessAttestation):Promise<void>{verifyCutoverReceipt(resolver,value);verifyPromotionReadinessAttestation(resolver,readiness);if(value.phase!=='ACTIVE'||readiness.fencedDigest!==value.prevStateDigest||readiness.targetEpoch!==value.targetEpoch||readiness.streamId!==value.streamId)throw new ContractValidationError('source activation requires matching ACTIVE and readiness receipts');await db.transaction(async exec=>{const systemId=String((await exec.query('SELECT system_identifier::text value FROM pg_catalog.pg_control_system()')).rows[0]?.value);if(readiness.targetSystemId!==systemId)throw new ContractValidationError('readiness receipt belongs to a different PostgreSQL authority');const result=await exec.query('INSERT INTO bpc_ha.source_activation(stream_id,epoch,state_digest_signed,key_id,signature,receipt,readiness) VALUES($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb) ON CONFLICT(stream_id) DO UPDATE SET epoch=EXCLUDED.epoch,state_digest_signed=EXCLUDED.state_digest_signed,key_id=EXCLUDED.key_id,signature=EXCLUDED.signature,receipt=EXCLUDED.receipt,readiness=EXCLUDED.readiness WHERE bpc_ha.source_activation.epoch<EXCLUDED.epoch',[value.streamId,value.targetEpoch,value.stateDigestSigned,value.keyId,value.signature,JSON.stringify(value),JSON.stringify(readiness)]);if(result.rowCount!==1){const existing=(await exec.query('SELECT epoch,state_digest_signed FROM bpc_ha.source_activation WHERE stream_id=$1',[value.streamId])).rows[0];if(!existing||safeInt(existing.epoch,'existing activation epoch',2,MAX_EPOCH)!==value.targetEpoch||String(existing.state_digest_signed)!==value.stateDigestSigned)throw new ContractValidationError('source ACTIVE receipt did not advance');}});}
const CUTOVER_COLS='stream_id,command_id,phase,previous_epoch,target_epoch,target_node_id,target_source_epoch,manifest_digest,final_source_sequence,state_digest,redis_claim_digest,old_lease_digest,old_lease_expires_at_ms,source_transaction_window_ms,prev_state_digest,state_digest_signed,key_id,signature';
const cutoverValues=(v:CutoverReceipt):unknown[]=>[v.streamId,v.commandId,v.phase,v.previousEpoch,v.targetEpoch,v.targetNodeId,v.targetSourceEpoch,v.manifestDigest,v.finalSourceSequence,v.stateDigest,v.redisClaimDigest,v.oldLeaseDigest,v.oldLeaseExpiresAtMs,v.sourceTransactionWindowMs,v.prevStateDigest,v.stateDigestSigned,v.keyId,v.signature];
const cutoverFromRow=(r:Record<string,unknown>):CutoverReceipt=>({streamId:String(r.stream_id),commandId:String(r.command_id),phase:String(r.phase) as CutoverPhase,previousEpoch:safeInt(r.previous_epoch,'previousEpoch',0,MAX_EPOCH-1),targetEpoch:safeInt(r.target_epoch,'targetEpoch',1,MAX_EPOCH),targetNodeId:String(r.target_node_id),targetSourceEpoch:String(r.target_source_epoch),manifestDigest:String(r.manifest_digest),finalSourceSequence:safeInt(r.final_source_sequence,'finalSourceSequence'),stateDigest:String(r.state_digest),redisClaimDigest:String(r.redis_claim_digest),oldLeaseDigest:String(r.old_lease_digest),oldLeaseExpiresAtMs:safeInt(r.old_lease_expires_at_ms,'oldLeaseExpiresAtMs',0,MAX_MS),sourceTransactionWindowMs:safeInt(r.source_transaction_window_ms,'sourceTransactionWindowMs',1,300_000),prevStateDigest:r.prev_state_digest===null?null:String(r.prev_state_digest),stateDigestSigned:String(r.state_digest_signed),keyId:String(r.key_id),signature:String(r.signature)});
async function verifyCutoverChain(exec:PgExecutor,resolver:PublicKeyResolver,streamId:string):Promise<CutoverReceipt|null>{const rows=(await exec.query(`SELECT ${CUTOVER_COLS} FROM bpc_ha.cutover_history WHERE stream_id=$1 ORDER BY target_epoch,CASE phase WHEN 'PREPARING' THEN 1 WHEN 'FENCED' THEN 2 ELSE 3 END`,[streamId])).rows;let previous:string|null=null,last:CutoverReceipt|null=null;for(const row of rows){const receipt=cutoverFromRow(row);verifyCutoverReceipt(resolver,receipt);if(receipt.prevStateDigest!==previous)throw new ContractValidationError('cutover retained history chain is broken');previous=receipt.stateDigestSigned;last=receipt;}const headRow=(await exec.query(`SELECT ${CUTOVER_COLS} FROM bpc_ha.cutover_head WHERE stream_id=$1`,[streamId])).rows[0];if(!headRow)return last?Promise.reject(new ContractValidationError('cutover history exists without authority head')):null;const head=cutoverFromRow(headRow);verifyCutoverReceipt(resolver,head);if(!last||head.stateDigestSigned!==last.stateDigestSigned)throw new ContractValidationError('cutover head is not the latest retained history state');return head;}
export function redisFenceRecordDigest(v:RedisFenceRecord):string{return sha256(frame('bpc-redis-record-digest/v1',canonicalize(v)));}

/** Durable external cutover witness. PREPARING is written before Redis changes;
 * FENCED requires expiry of the old signed lease on the control-DB clock plus
 * an exact signed Redis quorum record. ACTIVE is a separate signed CAS. */
export class BpcCutoverController {
  private constructor(private readonly db:PgTransactor,private readonly resolver:PublicKeyResolver,private readonly guardKeyId:string,private readonly guardKey:KeyObject|string,private readonly maxClockSkewMs=5_000){safeInt(maxClockSkewMs,'maxClockSkewMs',0,60_000);}
  static async open(db:PgTransactor,ready:BpcHaReadyToken,resolver:PublicKeyResolver,guardKeyId:string,guardKey:KeyObject|string,maxClockSkewMs=5_000):Promise<BpcCutoverController>{await requireBpcHaReady(ready,db);return new BpcCutoverController(db,resolver,guardKeyId,guardKey,maxClockSkewMs);}
  async begin(input:Omit<BareCutover,'phase'|'prevStateDigest'>):Promise<CutoverReceipt>{
    return this.db.transaction(async exec=>{await exec.query('SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1,0))',[input.streamId]);const head=(await exec.query(`SELECT ${CUTOVER_COLS} FROM bpc_ha.cutover_head WHERE stream_id=$1 FOR UPDATE`,[input.streamId])).rows[0];let current:CutoverReceipt|null=null;if(head){current=cutoverFromRow(head);verifyCutoverReceipt(this.resolver,current);const same=current.commandId===input.commandId&&current.previousEpoch===input.previousEpoch&&current.targetEpoch===input.targetEpoch&&current.targetNodeId===input.targetNodeId&&current.targetSourceEpoch===input.targetSourceEpoch&&current.manifestDigest===input.manifestDigest&&current.finalSourceSequence===input.finalSourceSequence&&current.stateDigest===input.stateDigest&&current.redisClaimDigest===input.redisClaimDigest&&current.oldLeaseDigest===input.oldLeaseDigest&&current.oldLeaseExpiresAtMs===input.oldLeaseExpiresAtMs&&current.sourceTransactionWindowMs===input.sourceTransactionWindowMs;if(same)return current;if(current.phase!=='ACTIVE'||input.previousEpoch!==current.targetEpoch)throw new ContractValidationError('another cutover intent is already authoritative');}
      const witness=(await exec.query('SELECT epoch,state_digest FROM bpc_ha.epoch_witness WHERE stream_id=$1 FOR UPDATE',[input.streamId])).rows[0];const epoch=witness?safeInt(witness.epoch,'witnessEpoch',0,MAX_EPOCH):0;if(epoch!==input.previousEpoch)throw new ContractValidationError('cutover does not advance the external epoch witness');
      if(!witness)await exec.query("INSERT INTO bpc_ha.epoch_witness(stream_id,epoch,state_digest) VALUES($1,0,repeat('0',64))",[input.streamId]);
      const preparing=signCutoverReceipt(this.guardKeyId,this.guardKey,{...input,phase:'PREPARING',prevStateDigest:current?.stateDigestSigned??null});verifyCutoverReceipt(this.resolver,preparing);const vals=cutoverValues(preparing);if((await exec.query(`INSERT INTO bpc_ha.cutover_history(${CUTOVER_COLS}) VALUES(${vals.map((_,i)=>'$'+(i+1)).join(',')})`,vals)).rowCount!==1)throw new ContractValidationError('cutover history insert failed');if(!current){if((await exec.query(`INSERT INTO bpc_ha.cutover_head(${CUTOVER_COLS}) VALUES(${vals.map((_,i)=>'$'+(i+1)).join(',')})`,vals)).rowCount!==1)throw new ContractValidationError('cutover head insert failed');}else if((await exec.query(`UPDATE bpc_ha.cutover_head SET command_id=$2,phase=$3,previous_epoch=$4,target_epoch=$5,target_node_id=$6,target_source_epoch=$7,manifest_digest=$8,final_source_sequence=$9,state_digest=$10,redis_claim_digest=$11,old_lease_digest=$12,old_lease_expires_at_ms=$13,source_transaction_window_ms=$14,prev_state_digest=$15,state_digest_signed=$16,key_id=$17,signature=$18 WHERE stream_id=$1 AND state_digest_signed=$19`,[...vals,current.stateDigestSigned])).rowCount!==1)throw new ContractValidationError('cutover admission forward-CAS failed');return preparing;});
  }
  private async transition(commandId:string,phase:'FENCED'|'ACTIVE',quorum?:BpcRedisQuorumFenceStore):Promise<CutoverReceipt>{return this.db.transaction(async exec=>{const row=(await exec.query(`SELECT ${CUTOVER_COLS},(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint::text control_now FROM bpc_ha.cutover_head WHERE command_id=$1 FOR UPDATE`,[commandId])).rows[0];if(!row)throw new ContractValidationError('cutover intent missing');const current=cutoverFromRow(row);verifyCutoverReceipt(this.resolver,current);const alreadyFenced=phase==='FENCED'&&(current.phase==='FENCED'||current.phase==='ACTIVE');if(phase==='ACTIVE'&&current.phase==='ACTIVE')return current;if((phase==='FENCED'&&!['PREPARING','FENCED','ACTIVE'].includes(current.phase))||(phase==='ACTIVE'&&current.phase!=='FENCED'))throw new ContractValidationError('cutover phase transition out of order');
      if(phase==='FENCED'){
        const leaseRow=(await exec.query(`SELECT ${LEASE_COLS} FROM bpc_ha.source_lease WHERE stream_id=$1`,[current.streamId])).rows[0];if(!leaseRow)throw new ContractValidationError('old source lease evidence missing');const lease=leaseFromRow(leaseRow);verifySourceLeaseGrant(this.resolver,lease);if(lease.status!=='revoked'||lease.grantDigest!==current.oldLeaseDigest||lease.epoch!==current.previousEpoch||lease.expiresAtMs!==current.oldLeaseExpiresAtMs)throw new ContractValidationError('old source lease is not exactly revoked');const controlNow=safeInt(row.control_now,'control clock',0,MAX_MS);if(controlNow<lease.expiresAtMs+this.maxClockSkewMs+current.sourceTransactionWindowMs)throw new ContractValidationError('old source lease expiry plus signed transaction window has not been proven');if(!quorum)throw new ContractValidationError('Redis quorum required');const redis=await quorum.currentForControl(CONTROL_REDIS_READ);if(redis.streamId!==current.streamId||redis.epoch!==current.targetEpoch||redis.nodeId!==current.targetNodeId||redis.commandId!==current.commandId||redisFenceRecordDigest(redis)!==current.redisClaimDigest)throw new ContractValidationError('Redis quorum does not match the signed cutover intent');
        if(alreadyFenced){const verified=await verifyCutoverChain(exec,this.resolver,current.streamId);const witness=(await exec.query('SELECT epoch,state_digest FROM bpc_ha.epoch_witness WHERE stream_id=$1 FOR SHARE',[current.streamId])).rows[0];if(!verified||verified.stateDigestSigned!==current.stateDigestSigned||!witness||safeInt(witness.epoch,'witnessEpoch',1,MAX_EPOCH)!==current.targetEpoch||String(witness.state_digest)!==current.stateDigestSigned)throw new ContractValidationError('FENCED retry lost its signed PostgreSQL witness');return current;}
      }
      const next=signCutoverReceipt(this.guardKeyId,this.guardKey,{...current,phase,prevStateDigest:current.stateDigestSigned});const vals=cutoverValues(next);if((await exec.query(`INSERT INTO bpc_ha.cutover_history(${CUTOVER_COLS}) VALUES(${vals.map((_,i)=>'$'+(i+1)).join(',')})`,vals)).rowCount!==1)throw new ContractValidationError('cutover history transition failed');if((await exec.query(`UPDATE bpc_ha.cutover_head SET command_id=$2,phase=$3,previous_epoch=$4,target_epoch=$5,target_node_id=$6,target_source_epoch=$7,manifest_digest=$8,final_source_sequence=$9,state_digest=$10,redis_claim_digest=$11,old_lease_digest=$12,old_lease_expires_at_ms=$13,source_transaction_window_ms=$14,prev_state_digest=$15,state_digest_signed=$16,key_id=$17,signature=$18 WHERE stream_id=$1 AND state_digest_signed=$19`,[...vals,current.stateDigestSigned])).rowCount!==1)throw new ContractValidationError('cutover head forward-CAS failed');if(phase==='FENCED'){const witness=await exec.query('UPDATE bpc_ha.epoch_witness SET epoch=$2,state_digest=$3 WHERE stream_id=$1 AND epoch=$4',[next.streamId,next.targetEpoch,next.stateDigestSigned,next.previousEpoch]);if(witness.rowCount!==1)throw new ContractValidationError('epoch witness forward-CAS failed');}return next;});}
  async markFenced(commandId:string,quorum:BpcRedisQuorumFenceStore):Promise<CutoverReceipt>{return this.transition(commandId,'FENCED',quorum);}
  async markActive(commandId:string,attestation:PromotionReadinessAttestation,sourceResolver:PublicKeyResolver):Promise<CutoverReceipt>{verifyPromotionReadinessAttestation(sourceResolver,attestation);const head=await this.db.transaction(async exec=>{const row=(await exec.query(`SELECT ${CUTOVER_COLS} FROM bpc_ha.cutover_head WHERE command_id=$1 FOR SHARE`,[commandId])).rows[0];if(!row)throw new ContractValidationError('cutover intent missing');return cutoverFromRow(row);});verifyCutoverReceipt(this.resolver,head);if(attestation.keyId!==attestation.snapshotKeyId||attestation.keyId===head.keyId||publicKeyFingerprint(sourceResolver,attestation.keyId)===publicKeyFingerprint(this.resolver,head.keyId))throw new ContractValidationError('promotion readiness must be signed by the independent snapshot authority');if(head.phase==='ACTIVE'){const existing=await this.db.transaction(async exec=>(await exec.query('SELECT attestation_digest FROM bpc_ha.promotion_attestation WHERE command_id=$1',[commandId])).rows[0]);if(!existing||String(existing.attestation_digest)!==attestation.attestationDigest)throw new ContractValidationError('ACTIVE retry has conflicting readiness evidence');return head;}if(head.phase!=='FENCED'||attestation.commandId!==commandId||attestation.streamId!==head.streamId||attestation.targetEpoch!==head.targetEpoch||attestation.targetSourceEpoch!==head.targetSourceEpoch||attestation.manifestDigest!==head.manifestDigest||attestation.appliedSequence!==head.finalSourceSequence||attestation.stateDigest!==head.stateDigest||attestation.fencedDigest!==head.stateDigestSigned)throw new ContractValidationError('promotion readiness attestation does not bind the FENCED cutover');await this.db.transaction(async exec=>{const inserted=await exec.query('INSERT INTO bpc_ha.promotion_attestation(command_id,attestation_digest,key_id,signature,payload) VALUES($1,$2,$3,$4,$5::jsonb) ON CONFLICT(command_id) DO NOTHING',[commandId,attestation.attestationDigest,attestation.keyId,attestation.signature,JSON.stringify(attestation)]);if(inserted.rowCount!==1){const existing=(await exec.query('SELECT attestation_digest FROM bpc_ha.promotion_attestation WHERE command_id=$1',[commandId])).rows[0];if(!existing||String(existing.attestation_digest)!==attestation.attestationDigest)throw new ContractValidationError('conflicting promotion readiness attestation');}});return this.transition(commandId,'ACTIVE');}
}

/** Binds Redis majority state to the external PostgreSQL epoch witness and the
 * latest verified cutover history. Empty/rollback/future state fails closed. */
export class PgRedisFenceWitness{
  private constructor(private readonly db:PgTransactor,private readonly resolver:PublicKeyResolver){}
  static async open(db:PgTransactor,ready:BpcHaReadyToken,resolver:PublicKeyResolver):Promise<PgRedisFenceWitness>{await requireBpcHaReady(ready,db);const witness=new PgRedisFenceWitness(db,resolver);REDIS_WITNESS_CAPABILITIES.add(witness);return witness;}
  async pinMembership(runIds:string[]):Promise<void>{if(runIds.length<3||new Set(runIds).size!==runIds.length)throw new ContractValidationError('invalid Redis membership');const digest=sha256(frame('bpc-redis-membership/v1',...runIds));await this.db.transaction(async exec=>{const inserted=await exec.query('INSERT INTO bpc_ha.redis_membership(id,membership_digest) VALUES(1,$1) ON CONFLICT(id) DO NOTHING',[digest]);if(inserted.rowCount===0){const row=(await exec.query('SELECT membership_digest FROM bpc_ha.redis_membership WHERE id=1')).rows[0];if(!row||String(row.membership_digest)!==digest)throw new ContractValidationError('Redis membership substitution rejected');}});}
  async bootstrapGenesis(record:RedisFenceRecord):Promise<void>{if(record.epoch!==1)throw new ContractValidationError('Redis genesis must be epoch 1');verify(this.resolver,record.keyId,redisFenceMessage(record),record.signature);const digest=redisFenceRecordDigest(record);await this.db.transaction(async exec=>{const inserted=await exec.query('INSERT INTO bpc_ha.epoch_witness(stream_id,epoch,state_digest) VALUES($1,1,$2) ON CONFLICT(stream_id) DO NOTHING',[record.streamId,digest]);if(inserted.rowCount===0){const row=(await exec.query('SELECT epoch,state_digest FROM bpc_ha.epoch_witness WHERE stream_id=$1 FOR SHARE',[record.streamId])).rows[0];if(!row||safeInt(row.epoch,'genesis witness epoch',1,MAX_EPOCH)!==1||String(row.state_digest)!==digest)throw new ContractValidationError('conflicting governed Redis genesis');}});}
  async verify(record:RedisFenceRecord|null):Promise<void>{if(!record)throw new ContractValidationError('empty Redis fence state is not authoritative');await this.db.transaction(async exec=>{const witness=(await exec.query('SELECT epoch,state_digest FROM bpc_ha.epoch_witness WHERE stream_id=$1 FOR SHARE',[record.streamId])).rows[0];const epoch=witness?safeInt(witness.epoch,'witnessEpoch',0,MAX_EPOCH):0;if(epoch===0)throw new ContractValidationError('Redis genesis is not governed by a signed PostgreSQL witness');
      const headRow=(await exec.query(`SELECT ${CUTOVER_COLS} FROM bpc_ha.cutover_head WHERE stream_id=$1 FOR SHARE`,[record.streamId])).rows[0];
      if(record.epoch===epoch&&epoch===1&&!headRow){if(String(witness.state_digest)!==redisFenceRecordDigest(record))throw new ContractValidationError('Redis genesis disagrees with the external witness');return;}
      if(!headRow)throw new ContractValidationError('cutover authority head missing');const head=await verifyCutoverChain(exec,this.resolver,record.streamId);if(!head)throw new ContractValidationError('cutover authority chain missing');
      if(record.epoch===epoch){const fencedRow=(await exec.query(`SELECT ${CUTOVER_COLS} FROM bpc_ha.cutover_history WHERE stream_id=$1 AND target_epoch=$2 AND phase='FENCED'`,[record.streamId,epoch])).rows[0];if(!fencedRow)throw new ContractValidationError('signed FENCED witness history missing');const fenced=cutoverFromRow(fencedRow);verifyCutoverReceipt(this.resolver,fenced);const actualRedis=redisFenceRecordDigest(record);if(String(witness.state_digest)!==fenced.stateDigestSigned||actualRedis!==fenced.redisClaimDigest)throw new ContractValidationError(`Redis authority disagrees with signed epoch witness (witness=${String(witness.state_digest).slice(0,12)}, fenced=${fenced.stateDigestSigned.slice(0,12)}, redis=${actualRedis.slice(0,12)}, expected=${fenced.redisClaimDigest.slice(0,12)})`);return;}
      if(record.epoch===epoch+1&&head.phase==='PREPARING'&&head.targetEpoch===record.epoch&&head.redisClaimDigest===redisFenceRecordDigest(record))return;
      throw new ContractValidationError('Redis fence epoch is rollback, unapproved future, or conflicting');});}
}

export interface PairSnapshotManifest {
  streamId: string; sourceEpoch: string; finalSequence: number; sourceSystemId: string;
  stateDigest: string; historyDigest: string; issuedAtMs: number; keyId: string; signature: string;
}
export interface PairSnapshotBundle<Clean> { manifest: PairSnapshotManifest; records: OutboxRecord<Clean>[] }
type BareSnapshot = Omit<PairSnapshotManifest, 'keyId' | 'signature'>;
function snapshotMessage(value: BareSnapshot): Buffer {
  return frame('bpc-pair-snapshot/v1', value.streamId, value.sourceEpoch, value.finalSequence,
    value.sourceSystemId, value.stateDigest, value.historyDigest, value.issuedAtMs);
}
async function stateDigest(exec: PgExecutor): Promise<string> {
  const pairs = String((await exec.query("SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY id)::text,'[]') AS value FROM bpc_pairs t")).rows[0].value);
  const pending = String((await exec.query("SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY token)::text,'[]') AS value FROM bpc_pending t")).rows[0].value);
  return sha256(frame('bpc-pair-state/v1', pairs, pending));
}
export async function buildPairSnapshotBundle<Clean>(db: PgTransactor, streamId: string, throughSequence: number, keyId: string, key: KeyObject | string, now = Date.now): Promise<PairSnapshotBundle<Clean>> {
  id(streamId, STREAM_RE, 'streamId');
  return db.transaction(async (exec) => {
    const cp = (await exec.query('SELECT source_epoch,sequence FROM ha_outbox_source_checkpoint WHERE stream_id=$1 FOR SHARE', [streamId])).rows[0];
    if (!cp) throw new ContractValidationError('source checkpoint missing');
    const sourceSequence = safeInt(cp.sequence, 'sourceSequence');
    const finalSequence = safeInt(throughSequence, 'throughSequence');
    if (finalSequence !== sourceSequence) throw new ContractValidationError('snapshot must capture the locked committed source head exactly');
    const rows = (await exec.query('SELECT source_epoch,sequence,fence_token::text,op_digest,mutation FROM ha_outbox_rows WHERE stream_id=$1 AND source_epoch=$2 AND sequence<=$3 ORDER BY sequence', [streamId, String(cp.source_epoch), finalSequence])).rows;
    const records = rows.map((row): OutboxRecord<Clean> => ({ contractVersion:'1',streamId,sourceEpoch:String(row.source_epoch),sequence:safeInt(row.sequence,'sequence',1),fenceToken:String(row.fence_token),opDigest:String(row.op_digest),mutation:row.mutation as SanitizedMutation<Clean> }));
    if (records.length !== finalSequence || records.some((record,index)=>record.sequence!==index+1)) throw new ContractValidationError('snapshot history is not contiguous from genesis');
    const sourceSystemId = String((await exec.query('SELECT system_identifier::text AS value FROM pg_catalog.pg_control_system()')).rows[0].value);
    const bare: BareSnapshot = { streamId, sourceEpoch: String(cp.source_epoch), finalSequence, sourceSystemId, stateDigest: await stateDigest(exec), historyDigest: sha256(canonicalize(records)), issuedAtMs: safeInt(now(), 'issuedAtMs', 0, MAX_MS) };
    const manifest = { ...bare, keyId, signature: sign(keyId, key, snapshotMessage(bare)) };
    return { manifest, records };
  });
}
export async function buildPairSnapshotManifest(db: PgTransactor, streamId: string, keyId: string, key: KeyObject | string, now = Date.now): Promise<PairSnapshotManifest> {
  const cp = await db.transaction(async (exec) => safeInt((await exec.query('SELECT sequence FROM ha_outbox_source_checkpoint WHERE stream_id=$1', [streamId])).rows[0]?.sequence, 'sourceSequence'));
  return (await buildPairSnapshotBundle(db, streamId, cp, keyId, key, now)).manifest;
}
export function verifyPairSnapshotManifest(resolver: PublicKeyResolver, manifest: PairSnapshotManifest): void {
  id(manifest.streamId, STREAM_RE, 'streamId'); id(manifest.sourceEpoch, ID_RE, 'sourceEpoch');
  safeInt(manifest.finalSequence, 'finalSequence'); safeInt(manifest.issuedAtMs, 'issuedAtMs', 0, MAX_MS);
  if (!/^\d+$/.test(manifest.sourceSystemId) || !HEX64.test(manifest.stateDigest) || !HEX64.test(manifest.historyDigest)) throw new ContractValidationError('snapshot manifest malformed');
  verify(resolver, manifest.keyId, snapshotMessage(manifest), manifest.signature);
}
export function pairSnapshotManifestDigest(manifest:PairSnapshotManifest):string{return sha256(canonicalize(manifest));}

function verifyBundle<Clean>(resolver: PublicKeyResolver, bundle: PairSnapshotBundle<Clean>, sanitizer: Pick<MutationSanitizer<unknown,Clean>,'assertSanitized'>): void {
  verifyPairSnapshotManifest(resolver,bundle.manifest);
  if(bundle.records.length!==bundle.manifest.finalSequence||sha256(canonicalize(bundle.records))!==bundle.manifest.historyDigest)throw new ContractValidationError('snapshot history digest/length mismatch');
  for(let index=0;index<bundle.records.length;index++){
    const record=bundle.records[index];assertHeaderConformant(record);
    if(record.streamId!==bundle.manifest.streamId||record.sourceEpoch!==bundle.manifest.sourceEpoch||record.sequence!==index+1)throw new ContractValidationError('snapshot history is gapped/reordered/misbinding');
    sanitizer.assertSanitized(record.mutation);
    const digest=canonicalOpDigest<Clean>({streamId:record.streamId,sourceEpoch:record.sourceEpoch,sequence:record.sequence,fenceToken:record.fenceToken,mutation:record.mutation as SanitizedMutation<Clean>});
    if(digest!==record.opDigest)throw new ContractValidationError('snapshot record digest mismatch');
  }
}

/** Import a bounded canonical snapshot into an empty receiver authority. Every
 * record is independently sanitized, re-digested, and replayed in one
 * SERIALIZABLE transaction; any alteration/gap rolls the complete import back. */
export async function importPairSnapshotBundle<Clean>(db:PgTransactor,resolver:PublicKeyResolver,bundle:PairSnapshotBundle<Clean>,sanitizer:Pick<MutationSanitizer<unknown,Clean>,'assertSanitized'>,applier:MutationApplier<Clean>):Promise<void>{
  verifyBundle(resolver,bundle,sanitizer);
  await db.transaction(async(exec)=>{
    const pairCount=Number((await exec.query('SELECT count(*)::int n FROM bpc_pairs')).rows[0].n),pendingCount=Number((await exec.query('SELECT count(*)::int n FROM bpc_pending')).rows[0].n);
    if(pairCount!==0||pendingCount!==0)throw new ContractValidationError('snapshot import requires an empty pair authority');
    const cp=(await exec.query('SELECT source_epoch,sequence FROM ha_outbox_receiver_checkpoint WHERE stream_id=$1 FOR UPDATE',[bundle.manifest.streamId])).rows[0];
    if(!cp||String(cp.source_epoch)!==bundle.manifest.sourceEpoch||safeInt(cp.sequence,'receiverSequence')!==0)throw new ContractValidationError('snapshot import requires a genesis receiver checkpoint');
    for(const record of bundle.records){await applier.applyInTx(exec,record);const ins=await exec.query('INSERT INTO ha_outbox_applied(stream_id,source_epoch,sequence,op_digest) VALUES($1,$2,$3,$4)',[record.streamId,record.sourceEpoch,record.sequence,record.opDigest]);if(ins.rowCount!==1)throw new ContractValidationError('snapshot applied-history insert failed');}
    const last=bundle.records.at(-1)?.opDigest??null;
    const upd=await exec.query('UPDATE ha_outbox_receiver_checkpoint SET sequence=$2,last_digest=$3 WHERE stream_id=$1',[bundle.manifest.streamId,bundle.manifest.finalSequence,last]);if(upd.rowCount!==1)throw new ContractValidationError('snapshot checkpoint advance failed');
    if(await stateDigest(exec)!==bundle.manifest.stateDigest)throw new ContractValidationError('snapshot replay state digest mismatch');
  });
}

export async function promoteReceiverToSource(
  db: PgTransactor,
  sourceResolver: PublicKeyResolver,
  bundle: PairSnapshotBundle<unknown>,
  sanitizer: Pick<MutationSanitizer<unknown, unknown>, 'assertSanitized'>,
  targetEpoch: number,
  targetSourceEpoch: string,
  guardResolver: PublicKeyResolver,
  fencedReceipt: CutoverReceipt,
): Promise<void> {
  const manifest = bundle.manifest;
  verifyBundle(sourceResolver, bundle, sanitizer);
  verifyPairSnapshotManifest(sourceResolver, manifest); safeInt(targetEpoch, 'targetEpoch', 1, MAX_EPOCH); id(targetSourceEpoch, ID_RE, 'targetSourceEpoch');
  verifyCutoverReceipt(guardResolver, fencedReceipt);
  const manifestDigest=pairSnapshotManifestDigest(manifest);
  if(fencedReceipt.phase!=='FENCED'||fencedReceipt.streamId!==manifest.streamId||fencedReceipt.targetEpoch!==targetEpoch||fencedReceipt.targetSourceEpoch!==targetSourceEpoch||fencedReceipt.manifestDigest!==manifestDigest||fencedReceipt.finalSourceSequence!==manifest.finalSequence||fencedReceipt.stateDigest!==manifest.stateDigest)throw new ContractValidationError('signed FENCED receipt does not bind this promotion');
  await db.transaction(async (exec) => {
    const existing=(await exec.query('SELECT source_manifest_digest,final_source_sequence,state_digest,source_key_id,source_signature,guard_key_id,guard_signature FROM bpc_ha.promotion_receipt WHERE stream_id=$1 AND target_epoch=$2 FOR SHARE',[manifest.streamId,targetEpoch])).rows[0];
    if(existing){const fence=(await exec.query('SELECT fence_token::text value FROM ha_outbox_fence WHERE stream_id=$1',[manifest.streamId])).rows[0];const source=(await exec.query('SELECT source_epoch FROM ha_outbox_source_checkpoint WHERE stream_id=$1',[manifest.streamId])).rows[0];if(String(existing.source_manifest_digest)!==manifestDigest||safeInt(existing.final_source_sequence,'existing final sequence')!==manifest.finalSequence||String(existing.state_digest)!==manifest.stateDigest||String(existing.source_key_id)!==manifest.keyId||String(existing.source_signature)!==manifest.signature||String(existing.guard_key_id)!==fencedReceipt.keyId||String(existing.guard_signature)!==fencedReceipt.signature||!fence||safeInt(fence.value,'existing fence')!==targetEpoch||!source||String(source.source_epoch)!==targetSourceEpoch)throw new ContractValidationError('existing promotion conflicts with exact retry');return;}
    const receiver = (await exec.query('SELECT source_epoch,sequence FROM ha_outbox_receiver_checkpoint WHERE stream_id=$1 FOR SHARE', [manifest.streamId])).rows[0];
    if (!receiver || String(receiver.source_epoch) !== manifest.sourceEpoch || safeInt(receiver.sequence, 'receiverSequence') !== manifest.finalSequence) {
      throw new ContractValidationError('receiver has not applied the complete frozen source tail');
    }
    const applied = (await exec.query('SELECT sequence,op_digest FROM ha_outbox_applied WHERE stream_id=$1 AND source_epoch=$2 AND sequence<=$3 ORDER BY sequence', [manifest.streamId, manifest.sourceEpoch, manifest.finalSequence])).rows;
    if (applied.length !== bundle.records.length || applied.some((row, index) => safeInt(row.sequence, 'applied sequence', 1) !== index + 1 || String(row.op_digest) !== bundle.records[index]?.opDigest)) {
      throw new ContractValidationError('receiver applied-history does not match the signed source history');
    }
    if (await stateDigest(exec) !== manifest.stateDigest) throw new ContractValidationError('receiver state does not match signed source snapshot');
    const fence = await exec.query('UPDATE ha_outbox_fence SET fence_token=$2 WHERE stream_id=$1 AND fence_token<$2', [manifest.streamId, String(targetEpoch)]);
    if (fence.rowCount !== 1) throw new ContractValidationError('promotion fence advance failed');
    const cp = await exec.query('INSERT INTO ha_outbox_source_checkpoint(stream_id,source_epoch,sequence) VALUES($1,$2,0) ON CONFLICT(stream_id) DO UPDATE SET source_epoch=EXCLUDED.source_epoch,sequence=0 WHERE ha_outbox_source_checkpoint.sequence=0', [manifest.streamId, targetSourceEpoch]);
    if (cp.rowCount !== 1) throw new ContractValidationError('promotion source checkpoint initialization failed');
    const receipt = await exec.query('INSERT INTO bpc_ha.promotion_receipt(stream_id,target_epoch,source_manifest_digest,final_source_sequence,state_digest,source_key_id,source_signature,guard_key_id,guard_signature) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)', [manifest.streamId,targetEpoch,manifestDigest,manifest.finalSequence,manifest.stateDigest,manifest.keyId,manifest.signature,fencedReceipt.keyId,fencedReceipt.signature]);
    if (receipt.rowCount !== 1) throw new ContractValidationError('promotion receipt insert failed');
  });
}
