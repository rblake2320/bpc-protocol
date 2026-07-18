/**
 * Atomic PostgreSQL pair authority + encrypted durable replication (#16).
 *
 * The operational `secretHash` is an HMAC key, not harmless metadata. Set
 * mutations therefore carry only an AES-256-GCM sealed payload. Sealing and
 * caller snapshots happen before the database transaction; authenticated local
 * opening happens synchronously inside the receiver transaction. No KMS/network
 * await is permitted while database locks are held.
 *
 * This is single-node mechanism evidence. Two-node failover, promotion,
 * snapshot/tail resync and measured RPO/RTO remain issue #16 gates.
 */
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { types as utilTypes } from 'node:util';

import {
  ContractValidationError,
  canonicalize,
  type MutationSanitizer,
  type OutboxRecord,
  type PublisherBackpressure,
  type SanitizedMutation,
} from './ha-outbox-contract.js';
import {
  PgDurableOutbox,
  type MutationApplier,
  type PgExecutor,
  type PgTransactor,
  type SchemaReadyToken,
} from './ha-outbox-pg.js';
import type { PairStore } from './store.js';
import type { PairRegistration, StoredPair } from './types.js';

const PAIR_KEYS = ['id','name','scope','mode','secretHash','pubJwk','status','created','lastActive','requests','failedSigs','cumulativeFailures','firstFailureAt','expiresAt','maxRequests','kind','canaryClass'] as const;
const REG_KEYS = ['name','scope','mode','secretHash','pubJwk','expiresAt','maxRequests','kind','canaryClass'] as const;
const JWK_KEYS = ['kty','crv','x','y','key_ops','ext'] as const;
const SEALED_KEYS = ['alg','keyId','nonce','ciphertext','tag'] as const;
const ID = /^[A-Za-z0-9_-]{1,64}$/;
// A 32-byte unpadded base64url value is 43 characters. Its final character
// has two zero padding bits, so only every fourth alphabet symbol is canonical.
const B64URL_256 = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;
const B64URL = /^[A-Za-z0-9_-]+$/;
const SCOPES = new Set(['read','read-write','admin']);
const MODES = new Set(['development','production']);
const STATUSES = new Set(['active','locked','expired','rotated','revoked']);
const KINDS = new Set(['legitimate','ghost']);
const CANARIES = new Set(['env_file','docs','registry_exfil']);

export interface CanonicalPublicJwk { kty: 'EC'; crv: 'P-256'; x: string; y: string }
export interface CanonicalPairRegistration extends Omit<PairRegistration, 'pubJwk'> { pubJwk: CanonicalPublicJwk }
export interface CanonicalStoredPair extends Omit<StoredPair, 'pubJwk' | 'cumulativeFailures'> {
  pubJwk: CanonicalPublicJwk;
  /** Decimal text gives canonical integer-only JSON a lossless JS-number round trip. */
  cumulativeFailures?: string;
}
export interface SealedPairPayload { alg: 'A256GCM'; keyId: string; nonce: string; ciphertext: string; tag: string }
interface PairSetAad { domain:'bpc-pair-payload'; version:'1'; streamId:string; kind:'bpc.pair.set.v1'; pairId:string }
interface PendingSetAad { domain:'bpc-pair-payload'; version:'1'; streamId:string; kind:'bpc.pending.set.v1'; token:string; requestedAt:number }

export type BpcPairMutation =
  | { kind: 'bpc.pair.set.v1'; pairId: string; sealed: SealedPairPayload }
  | { kind: 'bpc.pair.delete.v1'; pairId: string }
  | { kind: 'bpc.pending.set.v1'; token: string; requestedAt: number; sealed: SealedPairPayload }
  | { kind: 'bpc.pending.delete.v1'; token: string };

export interface PairPayloadCodec {
  sealPair(pair: CanonicalStoredPair, aad: PairSetAad): SealedPairPayload;
  openPair(sealed: SealedPairPayload, aad: PairSetAad): CanonicalStoredPair;
  sealRegistration(registration: CanonicalPairRegistration, aad: PendingSetAad): SealedPairPayload;
  openRegistration(sealed: SealedPairPayload, aad: PendingSetAad): CanonicalPairRegistration;
}
export interface PairSealKeyring { activeKeyId:string; resolveKey:(keyId:string)=>Buffer }

function dataObject(value: unknown, allowed: readonly string[], label: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || utilTypes.isProxy(value)) throw new ContractValidationError(`${label} must be a non-proxy object`);
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) throw new ContractValidationError(`${label} must be a plain object`);
  if (Object.getOwnPropertySymbols(value).length) throw new ContractValidationError(`${label} cannot contain symbols`);
  for (const key of Object.getOwnPropertyNames(value)) {
    if (!allowed.includes(key)) throw new ContractValidationError(`${label} contains unexpected field '${key}'`);
    const descriptor = Object.getOwnPropertyDescriptor(value, key)!;
    if (!('value' in descriptor) || !descriptor.enumerable) throw new ContractValidationError(`${label}.${key} must be an enumerable data property`);
  }
  return value as Record<string, unknown>;
}
function reqString(obj: Record<string, unknown>, key: string, label: string, max: number): string {
  const value = ownValue(obj, key);
  if (typeof value !== 'string' || value.length < 1 || value.length > max) throw new ContractValidationError(`${label}.${key} is invalid`);
  return value;
}
function optInt(obj: Record<string, unknown>, key: string, label: string): number | undefined {
  const value = ownValue(obj, key);
  if (value === undefined) return undefined;
  if (!Number.isSafeInteger(value) || (value as number) < 0) throw new ContractValidationError(`${label}.${key} must be a non-negative safe integer`);
  return value as number;
}
function reqInt(obj: Record<string, unknown>, key: string, label: string): number {
  const value = optInt(obj, key, label); if (value === undefined) throw new ContractValidationError(`${label}.${key} is required`); return value;
}
function ownValue(obj: Record<string, unknown>, key: string): unknown { return Object.getOwnPropertyDescriptor(obj, key)?.value; }
function finiteNumberToDecimal(value: number): string {
  if (!Number.isFinite(value) || value < 0) throw new ContractValidationError('pair.cumulativeFailures is invalid');
  if (Object.is(value, -0) || value === 0) return '0';
  const text = String(value);
  if (!/[eE]/.test(text)) return text;
  const [coefficient, exponentText] = text.toLowerCase().split('e');
  const exponent = Number(exponentText), [whole, fraction = ''] = coefficient.split('.');
  const digits = whole + fraction, point = whole.length + exponent;
  if (point <= 0) return `0.${'0'.repeat(-point)}${digits}`;
  if (point >= digits.length) return digits + '0'.repeat(point - digits.length);
  return `${digits.slice(0, point)}.${digits.slice(point)}`;
}
function databaseFloatToDecimal(value: unknown): string {
  if (typeof value !== 'number' && typeof value !== 'string') throw new ContractValidationError('database cumulativeFailures is invalid');
  const parsed = Number(value);
  return finiteNumberToDecimal(parsed);
}

function normalizeJwk(value: unknown): CanonicalPublicJwk {
  const jwk = dataObject(value, JWK_KEYS, 'pubJwk');
  const kty = ownValue(jwk, 'kty'), crv = ownValue(jwk, 'crv');
  const x = ownValue(jwk, 'x'), y = ownValue(jwk, 'y');
  if (kty !== 'EC' || crv !== 'P-256' || typeof x !== 'string' || !B64URL_256.test(x) || typeof y !== 'string' || !B64URL_256.test(y)) throw new ContractValidationError('pubJwk must be an exact public P-256 key (private d is forbidden)');
  const keyOps = ownValue(jwk, 'key_ops');
  if (keyOps !== undefined) {
    if (!Array.isArray(keyOps) || utilTypes.isProxy(keyOps) || keyOps.length !== 1 || Object.getOwnPropertySymbols(keyOps).length || Object.getOwnPropertyNames(keyOps).some((key) => key !== '0' && key !== 'length')) throw new ContractValidationError('pubJwk.key_ops must be exactly ["verify"]');
    const descriptor = Object.getOwnPropertyDescriptor(keyOps, '0');
    if (!descriptor || !('value' in descriptor) || !descriptor.enumerable || descriptor.value !== 'verify') throw new ContractValidationError('pubJwk.key_ops must contain exactly one verify data property');
  }
  const ext = ownValue(jwk, 'ext');
  if (ext !== undefined && ext !== true) throw new ContractValidationError('pubJwk.ext must be true when present');
  return Object.freeze({ kty: 'EC', crv: 'P-256', x, y });
}
function normalizeRegistration(value: unknown): CanonicalPairRegistration {
  const r = dataObject(value, REG_KEYS, 'registration');
  const scope = reqString(r, 'scope', 'registration', 10) as StoredPair['scope'];
  const mode = reqString(r, 'mode', 'registration', 16) as StoredPair['mode'];
  const kind = (ownValue(r, 'kind') ?? 'legitimate') as StoredPair['kind'];
  const canary = ownValue(r, 'canaryClass') as StoredPair['canaryClass'];
  if (!SCOPES.has(scope) || !MODES.has(mode) || !KINDS.has(kind!)) throw new ContractValidationError('registration enum is invalid');
  if (kind === 'ghost' ? !CANARIES.has(canary as string) : canary !== undefined) throw new ContractValidationError('registration kind/canaryClass is inconsistent');
  const out: CanonicalPairRegistration = { name: reqString(r, 'name', 'registration', 128), scope, mode, secretHash: reqString(r, 'secretHash', 'registration', 43), pubJwk: normalizeJwk(ownValue(r, 'pubJwk')), kind };
  if (!B64URL_256.test(out.secretHash)) throw new ContractValidationError('registration.secretHash must be a 256-bit base64url key');
  const expiresAt = optInt(r, 'expiresAt', 'registration'); if (expiresAt !== undefined) out.expiresAt = expiresAt;
  const maxRequests = optInt(r, 'maxRequests', 'registration'); if (maxRequests !== undefined) out.maxRequests = maxRequests;
  if (canary !== undefined) out.canaryClass = canary;
  return Object.freeze(out);
}
function registrationFromPairObject(p: Record<string, unknown>): CanonicalPairRegistration {
  const candidate: Record<string, unknown> = { name: ownValue(p,'name'), scope: ownValue(p,'scope'), mode: ownValue(p,'mode'), secretHash: ownValue(p,'secretHash'), pubJwk: ownValue(p,'pubJwk') };
  for (const key of ['expiresAt','maxRequests','kind','canaryClass']) if (ownValue(p,key) !== undefined) candidate[key] = ownValue(p,key);
  return normalizeRegistration(candidate);
}
function normalizePair(value: unknown, cumulativeText: boolean): CanonicalStoredPair {
  const p = dataObject(value, PAIR_KEYS, 'pair');
  const reg = registrationFromPairObject(p);
  const id = reqString(p, 'id', 'pair', 64); const status = reqString(p, 'status', 'pair', 16) as StoredPair['status'];
  if (!ID.test(id) || !STATUSES.has(status)) throw new ContractValidationError('pair id/status is invalid');
  const lastActive = ownValue(p, 'lastActive'); if (lastActive !== null && (!Number.isSafeInteger(lastActive) || (lastActive as number) < 0)) throw new ContractValidationError('pair.lastActive is invalid');
  const firstFailureAt = ownValue(p, 'firstFailureAt'); if (firstFailureAt !== undefined && firstFailureAt !== null && (!Number.isSafeInteger(firstFailureAt) || (firstFailureAt as number) < 0)) throw new ContractValidationError('pair.firstFailureAt is invalid');
  const cumulative = ownValue(p, 'cumulativeFailures'); let cumulativeFailures: string | undefined;
  if (cumulative !== undefined) {
    if (cumulativeText) { if (typeof cumulative !== 'string' || !/^(?:0|[1-9]\d*)(?:\.\d+)?$/.test(cumulative) || !Number.isFinite(Number(cumulative))) throw new ContractValidationError('pair.cumulativeFailures decimal is invalid'); cumulativeFailures = cumulative; }
    else { if (typeof cumulative !== 'number') throw new ContractValidationError('pair.cumulativeFailures is invalid'); cumulativeFailures = finiteNumberToDecimal(cumulative); }
  }
  const out: CanonicalStoredPair = { ...reg, id, status, created: reqInt(p,'created','pair'), lastActive: lastActive as number | null, requests: reqInt(p,'requests','pair'), failedSigs: reqInt(p,'failedSigs','pair') };
  if (cumulativeFailures !== undefined) out.cumulativeFailures = cumulativeFailures;
  if (firstFailureAt !== undefined) out.firstFailureAt = firstFailureAt as number | null;
  return Object.freeze(out);
}

function normalizeSealed(value: unknown): SealedPairPayload {
  const s = dataObject(value, SEALED_KEYS, 'sealed payload');
  if (Object.getOwnPropertyNames(s).length !== SEALED_KEYS.length || ownValue(s, 'alg') !== 'A256GCM') throw new ContractValidationError('sealed payload shape/algorithm is invalid');
  const keyId = reqString(s,'keyId','sealed payload',128), nonce = reqString(s,'nonce','sealed payload',32), ciphertext = reqString(s,'ciphertext','sealed payload',1_500_000), tag = reqString(s,'tag','sealed payload',32);
  const canonical = (text:string, bytes?:number) => {
    if (!B64URL.test(text)) return false;
    const decoded=Buffer.from(text,'base64url');
    return (bytes===undefined || decoded.length===bytes) && decoded.toString('base64url')===text;
  };
  if (!B64URL.test(keyId) || !canonical(nonce,12) || !canonical(ciphertext) || !canonical(tag,16)) throw new ContractValidationError('sealed payload encoding is invalid');
  return Object.freeze({ alg: 'A256GCM', keyId, nonce, ciphertext, tag });
}
function normalizeMutation(value: unknown): SanitizedMutation<BpcPairMutation> {
  const root = dataObject(value, ['kind','pairId','token','requestedAt','sealed'], 'pair mutation');
  switch (ownValue(root,'kind')) {
    case 'bpc.pair.set.v1': { if (Object.getOwnPropertyNames(root).length !== 3) throw new ContractValidationError('pair.set shape is invalid'); const pairId=reqString(root,'pairId','pair mutation',64); if(!ID.test(pairId))throw new ContractValidationError('pairId invalid'); return Object.freeze({kind:'bpc.pair.set.v1',pairId,sealed:normalizeSealed(ownValue(root,'sealed'))}) as SanitizedMutation<BpcPairMutation>; }
    case 'bpc.pair.delete.v1': { if (Object.getOwnPropertyNames(root).length !== 2) throw new ContractValidationError('pair.delete shape is invalid'); const pairId=reqString(root,'pairId','pair mutation',64); if(!ID.test(pairId))throw new ContractValidationError('pairId invalid'); return Object.freeze({kind:'bpc.pair.delete.v1',pairId}) as SanitizedMutation<BpcPairMutation>; }
    case 'bpc.pending.set.v1': { if (Object.getOwnPropertyNames(root).length !== 4) throw new ContractValidationError('pending.set shape is invalid'); return Object.freeze({kind:'bpc.pending.set.v1',token:reqString(root,'token','pair mutation',256),requestedAt:reqInt(root,'requestedAt','pair mutation'),sealed:normalizeSealed(ownValue(root,'sealed'))}) as SanitizedMutation<BpcPairMutation>; }
    case 'bpc.pending.delete.v1': { if (Object.getOwnPropertyNames(root).length !== 2) throw new ContractValidationError('pending.delete shape is invalid'); return Object.freeze({kind:'bpc.pending.delete.v1',token:reqString(root,'token','pair mutation',256)}) as SanitizedMutation<BpcPairMutation>; }
    default: throw new ContractValidationError('unknown pair mutation kind');
  }
}
export const bpcPairMutationSanitizer: MutationSanitizer<BpcPairMutation,BpcPairMutation> = { sanitize: normalizeMutation, assertSanitized(value): asserts value is SanitizedMutation<BpcPairMutation> { normalizeMutation(value); } };

function aadBytes(value: object): Buffer { return Buffer.from(canonicalize(value), 'utf8'); }
export class Aes256GcmPairPayloadCodec implements PairPayloadCodec {
  constructor(private readonly activeKeyId: string, private readonly keyResolver: (keyId: string) => Buffer) {
    if (!B64URL.test(activeKeyId) || activeKeyId.length > 128) throw new ContractValidationError('active seal keyId is invalid');
  }
  private key(keyId: string): Buffer { const key=Buffer.from(this.keyResolver(keyId)); if(key.length!==32)throw new ContractValidationError('seal key must be exactly 32 bytes'); return key; }
  private seal(value: unknown, aad: object): SealedPairPayload {
    const nonce=randomBytes(12), key=this.key(this.activeKeyId);
    try {
      const cipher=createCipheriv('aes-256-gcm',key,nonce); cipher.setAAD(aadBytes({alg:'A256GCM',keyId:this.activeKeyId,...aad}));
      const ciphertext=Buffer.concat([cipher.update(canonicalize(value),'utf8'),cipher.final()]);
      return Object.freeze({alg:'A256GCM',keyId:this.activeKeyId,nonce:nonce.toString('base64url'),ciphertext:ciphertext.toString('base64url'),tag:cipher.getAuthTag().toString('base64url')});
    } finally { key.fill(0); }
  }
  private open(sealedValue: SealedPairPayload, aad: object): unknown {
    const sealed=normalizeSealed(sealedValue);
    let key: Buffer | undefined;
    try { key=this.key(sealed.keyId);const decipher=createDecipheriv('aes-256-gcm',key,Buffer.from(sealed.nonce,'base64url'));decipher.setAAD(aadBytes({alg:sealed.alg,keyId:sealed.keyId,...aad})); decipher.setAuthTag(Buffer.from(sealed.tag,'base64url')); return JSON.parse(Buffer.concat([decipher.update(Buffer.from(sealed.ciphertext,'base64url')),decipher.final()]).toString('utf8')); }
    catch { throw new ContractValidationError('sealed pair payload authentication failed'); }
    finally { key?.fill(0); }
  }
  private validateDomain(aad:{domain:string;version:string;streamId:string}){if(aad.domain!=='bpc-pair-payload'||aad.version!=='1'||!aad.streamId||aad.streamId.length>512)throw new ContractValidationError('pair payload domain/version/stream is invalid');}
  sealPair(pair: CanonicalStoredPair,aad:PairSetAad){this.validateDomain(aad);const clean=normalizePair(pair,true);if(clean.id!==aad.pairId)throw new ContractValidationError('pair identity/AAD mismatch');return this.seal(clean,aad);}
  openPair(sealed:SealedPairPayload,aad:PairSetAad){this.validateDomain(aad);if(!ID.test(aad.pairId))throw new ContractValidationError('pair AAD invalid');const pair=normalizePair(this.open(sealed,aad),true);if(pair.id!==aad.pairId)throw new ContractValidationError('sealed pair identity/AAD mismatch');return pair;}
  sealRegistration(reg:CanonicalPairRegistration,aad:PendingSetAad){this.validateDomain(aad);if(!aad.token||aad.token.length>256||!Number.isSafeInteger(aad.requestedAt)||aad.requestedAt<0)throw new ContractValidationError('pending AAD invalid');return this.seal(normalizeRegistration(reg),aad);}
  openRegistration(sealed:SealedPairPayload,aad:PendingSetAad){this.validateDomain(aad);if(!aad.token||aad.token.length>256||!Number.isSafeInteger(aad.requestedAt)||aad.requestedAt<0)throw new ContractValidationError('pending AAD invalid');return normalizeRegistration(this.open(sealed,aad));}
}

function affectedOne(result:{rowCount:number},label:string){if(result.rowCount!==1)throw new ContractValidationError(`${label} affected ${result.rowCount}; expected 1`);}
function affectedZeroOrOne(result:{rowCount:number},label:string){if(result.rowCount!==0&&result.rowCount!==1)throw new ContractValidationError(`${label} affected ${result.rowCount}; expected 0 or 1`);}
async function upsertPair(exec:PgExecutor,p:CanonicalStoredPair){affectedOne(await exec.query(`INSERT INTO bpc_pairs (id,name,scope,mode,secret_hash,pub_jwk,status,created,last_active,requests,failed_sigs,cumulative_failures,first_failure_at,max_requests,kind,canary_class,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) ON CONFLICT(id) DO UPDATE SET name=$2,scope=$3,mode=$4,secret_hash=$5,pub_jwk=$6,status=$7,created=$8,last_active=$9,requests=$10,failed_sigs=$11,cumulative_failures=$12,first_failure_at=$13,max_requests=$14,kind=$15,canary_class=$16,expires_at=$17`,[p.id,p.name,p.scope,p.mode,p.secretHash,JSON.stringify(p.pubJwk),p.status,p.created,p.lastActive,p.requests,p.failedSigs,p.cumulativeFailures??null,p.firstFailureAt??null,p.maxRequests??null,p.kind??'legitimate',p.canaryClass??null,p.expiresAt??null]),'pair upsert');}
async function upsertPending(exec:PgExecutor,token:string,r:CanonicalPairRegistration,requestedAt:number){affectedOne(await exec.query('INSERT INTO bpc_pending(token,registration,requested_at) VALUES($1,$2,$3) ON CONFLICT(token) DO UPDATE SET registration=$2,requested_at=$3',[token,JSON.stringify(r),requestedAt]),'pending upsert');}
function rowToPair(row:Record<string,unknown>):StoredPair{const canonical=normalizePair({id:String(row['id']),name:String(row['name']),scope:String(row['scope']),mode:String(row['mode']),secretHash:String(row['secret_hash']),pubJwk:row['pub_jwk'],status:String(row['status']),created:Number(row['created']),lastActive:row['last_active']==null?null:Number(row['last_active']),requests:Number(row['requests']),failedSigs:Number(row['failed_sigs']),...(row['cumulative_failures']==null?{}:{cumulativeFailures:databaseFloatToDecimal(row['cumulative_failures'])}),...(row['first_failure_at']==null?{}:{firstFailureAt:Number(row['first_failure_at'])}),...(row['max_requests']==null?{}:{maxRequests:Number(row['max_requests'])}),kind:String(row['kind']??'legitimate'),...(row['canary_class']==null?{}:{canaryClass:String(row['canary_class'])}),...(row['expires_at']==null?{}:{expiresAt:Number(row['expires_at'])})},true);return{...canonical,cumulativeFailures:canonical.cumulativeFailures===undefined?undefined:Number(canonical.cumulativeFailures)};}

export interface PgTransactionalPairStoreOptions { streamId:string; fenceToken:bigint; keyring:PairSealKeyring; maxPendingRows:number; backpressure?:PublisherBackpressure; scopeDeadlineMs?:number }
export class PgTransactionalPairStore implements PairStore {
  private readonly outbox:PgDurableOutbox<BpcPairMutation,BpcPairMutation>;
  private readonly codec:Aes256GcmPairPayloadCodec;
  constructor(db:PgTransactor,ready:SchemaReadyToken,private readonly opts:PgTransactionalPairStoreOptions){if(typeof opts.fenceToken!=='bigint'||opts.fenceToken<0n)throw new ContractValidationError('fenceToken invalid');this.codec=new Aes256GcmPairPayloadCodec(opts.keyring.activeKeyId,opts.keyring.resolveKey);this.outbox=new PgDurableOutbox(db,ready,{streamId:opts.streamId,sanitizer:bpcPairMutationSanitizer,maxPendingRows:opts.maxPendingRows,backpressure:opts.backpressure??'fail-authoritative-mutation',scopeDeadlineMs:opts.scopeDeadlineMs});}
  private async commit(m:BpcPairMutation,dml:(exec:PgExecutor)=>Promise<void>){const clean=normalizeMutation(m) as BpcPairMutation;await this.outbox.withOutboxTx(async(tx,exec)=>{await this.outbox.appendInTx(tx,{streamId:this.opts.streamId,rawMutation:clean,fenceToken:this.opts.fenceToken});await dml(exec);});}
  async get(id:string){if(!ID.test(id))throw new ContractValidationError('pairId invalid');return this.outbox.withOutboxTx(async(_t,e)=>{const r=(await e.query('SELECT * FROM bpc_pairs WHERE id=$1',[id])).rows[0];return r?rowToPair(r):undefined;});}
  async list(){return this.outbox.withOutboxTx(async(_t,e)=>(await e.query('SELECT * FROM bpc_pairs ORDER BY created DESC')).rows.map(rowToPair));}
  async set(value:StoredPair){const pair=normalizePair(value,false),aad={domain:'bpc-pair-payload' as const,version:'1' as const,streamId:this.opts.streamId,kind:'bpc.pair.set.v1' as const,pairId:pair.id},sealed=this.codec.sealPair(pair,aad);await this.commit({kind:aad.kind,pairId:aad.pairId,sealed},(e)=>upsertPair(e,pair));}
  async delete(pairId:string){if(!ID.test(pairId))throw new ContractValidationError('pairId invalid');await this.commit({kind:'bpc.pair.delete.v1',pairId},async(e)=>affectedZeroOrOne(await e.query('DELETE FROM bpc_pairs WHERE id=$1',[pairId]),'pair delete'));}
  async getPending(token:string){if(!token||token.length>256)throw new ContractValidationError('token invalid');return this.outbox.withOutboxTx(async(_t,e)=>{const r=(await e.query('SELECT * FROM bpc_pending WHERE token=$1',[token])).rows[0];return r?{registration:normalizeRegistration(r['registration']),requestedAt:reqInt({requestedAt:Number(r['requested_at'])},'requestedAt','pending')}:undefined;});}
  async listPending(){return this.outbox.withOutboxTx(async(_t,e)=>(await e.query('SELECT * FROM bpc_pending ORDER BY requested_at ASC')).rows.map(r=>({token:reqString({token:r['token']},'token','pending',256),registration:normalizeRegistration(r['registration']),requestedAt:reqInt({requestedAt:Number(r['requested_at'])},'requestedAt','pending')})));}
  async setPending(token:string,value:PairRegistration,requestedAt:number){if(!token||token.length>256||!Number.isSafeInteger(requestedAt)||requestedAt<0)throw new ContractValidationError('pending identity/time invalid');const registration=normalizeRegistration(value),aad={domain:'bpc-pair-payload' as const,version:'1' as const,streamId:this.opts.streamId,kind:'bpc.pending.set.v1' as const,token,requestedAt},sealed=this.codec.sealRegistration(registration,aad);await this.commit({kind:aad.kind,token,requestedAt,sealed},(e)=>upsertPending(e,token,registration,requestedAt));}
  async deletePending(token:string){if(!token||token.length>256)throw new ContractValidationError('token invalid');await this.commit({kind:'bpc.pending.delete.v1',token},async(e)=>affectedZeroOrOne(await e.query('DELETE FROM bpc_pending WHERE token=$1',[token]),'pending delete'));}
}

export class PgPairMutationApplier implements MutationApplier<BpcPairMutation>{private readonly codec:Aes256GcmPairPayloadCodec;constructor(private readonly streamId:string,keyring:PairSealKeyring){if(!streamId||streamId.length>512)throw new ContractValidationError('streamId invalid');this.codec=new Aes256GcmPairPayloadCodec(keyring.activeKeyId,keyring.resolveKey);}async applyInTx(exec:PgExecutor,record:OutboxRecord<BpcPairMutation>){if(record.streamId!==this.streamId)throw new ContractValidationError('pair mutation stream mismatch');const m=normalizeMutation(record.mutation) as BpcPairMutation;switch(m.kind){case'bpc.pair.set.v1':await upsertPair(exec,this.codec.openPair(m.sealed,{domain:'bpc-pair-payload',version:'1',streamId:this.streamId,kind:m.kind,pairId:m.pairId}));return;case'bpc.pair.delete.v1':affectedZeroOrOne(await exec.query('DELETE FROM bpc_pairs WHERE id=$1',[m.pairId]),'pair delete');return;case'bpc.pending.set.v1':await upsertPending(exec,m.token,this.codec.openRegistration(m.sealed,{domain:'bpc-pair-payload',version:'1',streamId:this.streamId,kind:m.kind,token:m.token,requestedAt:m.requestedAt}),m.requestedAt);return;case'bpc.pending.delete.v1':affectedZeroOrOne(await exec.query('DELETE FROM bpc_pending WHERE token=$1',[m.token]),'pending delete');return;}}}
