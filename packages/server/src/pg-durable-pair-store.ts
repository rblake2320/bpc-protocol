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
  type OutboxRecordHeader,
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
import { canonicalAuthorizationJwk, hasInitialPairState, pairMatchesRegistration, rotationPolicyMatches, successfulUsePolicyMatches, type AtomicPairStore, type PairAtomicMutation, type SuccessfulUseClaim, type SuccessfulUsePolicy } from './store.js';
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
interface PairSetAad { domain:'bpc-pair-payload'; version:'1'; streamId:string; kind:'bpc.pair.set.v1'|'bpc.pair.approve.v1'|'bpc.pair.rotate.v1'; pairId:string }
interface PendingSetAad { domain:'bpc-pair-payload'; version:'1'; streamId:string; kind:'bpc.pending.set.v1'|'bpc.pair.approve.v1'; token:string; requestedAt:number }

export type BpcPairMutation =
  | { kind: 'bpc.pair.set.v1'; pairId: string; sealed: SealedPairPayload }
  | { kind: 'bpc.pair.delete.v1'; pairId: string }
  | { kind: 'bpc.pending.set.v1'; token: string; requestedAt: number; sealed: SealedPairPayload }
  | { kind: 'bpc.pending.delete.v1'; token: string }
  | { kind: 'bpc.pair.approve.v1'; token: string; requestedAt: number; expectedPending: SealedPairPayload; pairId: string; sealed: SealedPairPayload }
  | { kind: 'bpc.pair.rotate.v1'; oldPairId: string; expectedOld: SealedPairPayload; newPairId: string; sealed: SealedPairPayload };

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
  try { return canonicalAuthorizationJwk(dataObject(value, JWK_KEYS, 'pubJwk')); }
  catch (error) { throw new ContractValidationError(error instanceof Error ? error.message : 'pubJwk is invalid'); }
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
  const root = dataObject(value, ['kind','pairId','token','requestedAt','sealed','expectedPending','oldPairId','expectedOld','newPairId'], 'pair mutation');
  switch (ownValue(root,'kind')) {
    case 'bpc.pair.set.v1': { if (Object.getOwnPropertyNames(root).length !== 3) throw new ContractValidationError('pair.set shape is invalid'); const pairId=reqString(root,'pairId','pair mutation',64); if(!ID.test(pairId))throw new ContractValidationError('pairId invalid'); return Object.freeze({kind:'bpc.pair.set.v1',pairId,sealed:normalizeSealed(ownValue(root,'sealed'))}) as SanitizedMutation<BpcPairMutation>; }
    case 'bpc.pair.delete.v1': { if (Object.getOwnPropertyNames(root).length !== 2) throw new ContractValidationError('pair.delete shape is invalid'); const pairId=reqString(root,'pairId','pair mutation',64); if(!ID.test(pairId))throw new ContractValidationError('pairId invalid'); return Object.freeze({kind:'bpc.pair.delete.v1',pairId}) as SanitizedMutation<BpcPairMutation>; }
    case 'bpc.pending.set.v1': { if (Object.getOwnPropertyNames(root).length !== 4) throw new ContractValidationError('pending.set shape is invalid'); return Object.freeze({kind:'bpc.pending.set.v1',token:reqString(root,'token','pair mutation',256),requestedAt:reqInt(root,'requestedAt','pair mutation'),sealed:normalizeSealed(ownValue(root,'sealed'))}) as SanitizedMutation<BpcPairMutation>; }
    case 'bpc.pending.delete.v1': { if (Object.getOwnPropertyNames(root).length !== 2) throw new ContractValidationError('pending.delete shape is invalid'); return Object.freeze({kind:'bpc.pending.delete.v1',token:reqString(root,'token','pair mutation',256)}) as SanitizedMutation<BpcPairMutation>; }
    case 'bpc.pair.approve.v1': { if (Object.getOwnPropertyNames(root).length !== 6) throw new ContractValidationError('pair.approve shape is invalid'); const pairId=reqString(root,'pairId','pair mutation',64);if(!ID.test(pairId))throw new ContractValidationError('pairId invalid');return Object.freeze({kind:'bpc.pair.approve.v1',token:reqString(root,'token','pair mutation',256),requestedAt:reqInt(root,'requestedAt','pair mutation'),expectedPending:normalizeSealed(ownValue(root,'expectedPending')),pairId,sealed:normalizeSealed(ownValue(root,'sealed'))}) as SanitizedMutation<BpcPairMutation>; }
    case 'bpc.pair.rotate.v1': { if (Object.getOwnPropertyNames(root).length !== 5) throw new ContractValidationError('pair.rotate shape is invalid');const oldPairId=reqString(root,'oldPairId','pair mutation',64),newPairId=reqString(root,'newPairId','pair mutation',64);if(!ID.test(oldPairId)||!ID.test(newPairId)||oldPairId===newPairId)throw new ContractValidationError('rotation identities invalid');return Object.freeze({kind:'bpc.pair.rotate.v1',oldPairId,expectedOld:normalizeSealed(ownValue(root,'expectedOld')),newPairId,sealed:normalizeSealed(ownValue(root,'sealed'))}) as SanitizedMutation<BpcPairMutation>; }
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
async function insertPair(exec:PgExecutor,p:CanonicalStoredPair){affectedOne(await exec.query(`INSERT INTO bpc_pairs (id,name,scope,mode,secret_hash,pub_jwk,status,created,last_active,requests,failed_sigs,cumulative_failures,first_failure_at,max_requests,kind,canary_class,expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,[p.id,p.name,p.scope,p.mode,p.secretHash,JSON.stringify(p.pubJwk),p.status,p.created,p.lastActive,p.requests,p.failedSigs,p.cumulativeFailures??null,p.firstFailureAt??null,p.maxRequests??null,p.kind??'legitimate',p.canaryClass??null,p.expiresAt??null]),'pair insert');}
async function upsertPending(exec:PgExecutor,token:string,r:CanonicalPairRegistration,requestedAt:number){affectedOne(await exec.query('INSERT INTO bpc_pending(token,registration,requested_at) VALUES($1,$2,$3) ON CONFLICT(token) DO UPDATE SET registration=$2,requested_at=$3',[token,JSON.stringify(r),requestedAt]),'pending upsert');}
function rowToPair(row:Record<string,unknown>):StoredPair{const canonical=normalizePair({id:String(row['id']),name:String(row['name']),scope:String(row['scope']),mode:String(row['mode']),secretHash:String(row['secret_hash']),pubJwk:row['pub_jwk'],status:String(row['status']),created:Number(row['created']),lastActive:row['last_active']==null?null:Number(row['last_active']),requests:Number(row['requests']),failedSigs:Number(row['failed_sigs']),...(row['cumulative_failures']==null?{}:{cumulativeFailures:databaseFloatToDecimal(row['cumulative_failures'])}),...(row['first_failure_at']==null?{}:{firstFailureAt:Number(row['first_failure_at'])}),...(row['max_requests']==null?{}:{maxRequests:Number(row['max_requests'])}),kind:String(row['kind']??'legitimate'),...(row['canary_class']==null?{}:{canaryClass:String(row['canary_class'])}),...(row['expires_at']==null?{}:{expiresAt:Number(row['expires_at'])})},true);return{...canonical,cumulativeFailures:canonical.cumulativeFailures===undefined?undefined:Number(canonical.cumulativeFailures)};}
function sameCanonical(left:unknown,right:unknown):boolean{return canonicalize(left)===canonicalize(right);}
function freezePair(pair:StoredPair):Readonly<StoredPair>{const copy=structuredClone(pair);Object.freeze(copy.pubJwk);return Object.freeze(copy);}
function assertApprovalPair(registration:CanonicalPairRegistration,pair:CanonicalStoredPair):void{if(!hasInitialPairState(pair as StoredPair)||!pairMatchesRegistration(pair as StoredPair,registration))throw new ContractValidationError('approved pair does not match pending registration/initial state');}

export interface PgTransactionalPairStoreOptions { streamId:string; fenceToken:bigint; keyring:PairSealKeyring; maxPendingRows:number; backpressure?:PublisherBackpressure; scopeDeadlineMs?:number }
const HA_FENCE_INTERNAL=Symbol('bpc.ha.pair.fence.internal');
type ControlledMutation=(exec:PgExecutor,header:OutboxRecordHeader,action:string,payload:readonly unknown[])=>Promise<{rows:Record<string,unknown>[];rowCount:number}>;
interface InternalHaFence { readonly [HA_FENCE_INTERNAL]:{check:(exec:PgExecutor)=>Promise<void>;mutate?:ControlledMutation;append?:NonNullable<ConstructorParameters<typeof PgDurableOutbox<BpcPairMutation,BpcPairMutation>>[2]['governedAppend']>} }
export class PgTransactionalPairStore implements AtomicPairStore {
  // Source-side compare/read phases deliberately avoid SELECT FOR UPDATE:
  // PostgreSQL requires UPDATE privilege for that syntax. The required
  // SERIALIZABLE transactor detects a conflicting writer, while governed
  // mutation functions retain the actual write locks under owner authority.
  private readonly outbox:PgDurableOutbox<BpcPairMutation,BpcPairMutation>;
  private readonly codec:Aes256GcmPairPayloadCodec;
  private readonly headers=new WeakMap<object,OutboxRecordHeader>();
  private readonly mutate?:ControlledMutation;
  constructor(db:PgTransactor,ready:SchemaReadyToken,private readonly opts:PgTransactionalPairStoreOptions,internal?:InternalHaFence){if(typeof opts.fenceToken!=='bigint'||opts.fenceToken<0n)throw new ContractValidationError('fenceToken invalid');this.codec=new Aes256GcmPairPayloadCodec(opts.keyring.activeKeyId,opts.keyring.resolveKey);const authority=internal?.[HA_FENCE_INTERNAL];this.mutate=authority?.mutate;const check=authority?.check??(async(exec:PgExecutor)=>{const present=(await exec.query("SELECT pg_catalog.to_regclass('bpc_ha.authority_stream')::text value")).rows[0]?.value;if(present){const row=(await exec.query('SELECT 1 FROM bpc_ha.authority_stream LIMIT 1')).rows[0];if(row)throw new ContractValidationError('HA-governed pair authority requires createHaPairAuthority');}});this.outbox=new PgDurableOutbox(db,ready,{streamId:opts.streamId,sanitizer:bpcPairMutationSanitizer,maxPendingRows:opts.maxPendingRows,backpressure:opts.backpressure??'fail-authoritative-mutation',scopeDeadlineMs:opts.scopeDeadlineMs,preCommitCheck:check,governedAppend:authority?.append});}
  private async append(tx:Parameters<PgDurableOutbox<BpcPairMutation,BpcPairMutation>['appendInTx']>[0],exec:PgExecutor,mutation:BpcPairMutation):Promise<OutboxRecordHeader>{const header=await this.outbox.appendInTx(tx,{streamId:this.opts.streamId,rawMutation:mutation,fenceToken:this.opts.fenceToken});this.headers.set(exec as object,header);return header;}
  private controlled(exec:PgExecutor):PgExecutor{if(!this.mutate)return exec;const mutate=this.mutate,header=this.headers.get(exec as object);if(!header)throw new ContractValidationError('controlled mutation requires a durable outbox row in the same transaction');return{query:async(sql:string,params:unknown[]=[])=>{const compact=sql.replace(/\s+/g,' ').trim().toLowerCase();if(compact.startsWith('insert into bpc_pairs'))return mutate(exec,header,compact.includes('on conflict')?'pair-upsert':'pair-insert',params);if(compact.startsWith('delete from bpc_pairs'))return mutate(exec,header,'pair-delete',params);if(compact.startsWith('insert into bpc_pending'))return mutate(exec,header,'pending-upsert',params);if(compact.startsWith('delete from bpc_pending'))return mutate(exec,header,'pending-delete',params);return exec.query(sql,params);}};}
  private async commit(m:BpcPairMutation,dml:(exec:PgExecutor)=>Promise<void>){const clean=normalizeMutation(m) as BpcPairMutation;await this.outbox.withOutboxTx(async(tx,exec)=>{await this.append(tx,exec,clean);await dml(this.controlled(exec));});}
  private async conditionalStatus(pairId:string,predicate:(pair:Readonly<StoredPair>)=>boolean,status:StoredPair['status']):Promise<boolean>{
    if(!ID.test(pairId))throw new ContractValidationError('pairId invalid');
    return this.outbox.withOutboxTx(async(tx,e)=>{
      const row=(await e.query('SELECT * FROM bpc_pairs WHERE id=$1',[pairId])).rows[0];if(!row)return false;
      const current=rowToPair(row);if(!predicate(freezePair(current)))return false;
      const next=normalizePair({...current,status},false),aad={domain:'bpc-pair-payload' as const,version:'1' as const,streamId:this.opts.streamId,kind:'bpc.pair.set.v1' as const,pairId};
      await this.append(tx,e,{kind:aad.kind,pairId,sealed:this.codec.sealPair(next,aad)});await upsertPair(this.controlled(e),next);return true;
    });
  }
  async get(id:string){if(!ID.test(id))throw new ContractValidationError('pairId invalid');return this.outbox.withOutboxTx(async(_t,e)=>{const r=(await e.query('SELECT * FROM bpc_pairs WHERE id=$1',[id])).rows[0];return r?rowToPair(r):undefined;});}
  async list(){return this.outbox.withOutboxTx(async(_t,e)=>(await e.query('SELECT * FROM bpc_pairs ORDER BY created DESC')).rows.map(rowToPair));}
  async set(value:StoredPair){const pair=normalizePair(value,false),aad={domain:'bpc-pair-payload' as const,version:'1' as const,streamId:this.opts.streamId,kind:'bpc.pair.set.v1' as const,pairId:pair.id},sealed=this.codec.sealPair(pair,aad);await this.commit({kind:aad.kind,pairId:aad.pairId,sealed},(e)=>upsertPair(e,pair));}
  async delete(pairId:string){if(!ID.test(pairId))throw new ContractValidationError('pairId invalid');await this.commit({kind:'bpc.pair.delete.v1',pairId},async(e)=>affectedZeroOrOne(await e.query('DELETE FROM bpc_pairs WHERE id=$1',[pairId]),'pair delete'));}
  async getPending(token:string){if(!token||token.length>256)throw new ContractValidationError('token invalid');return this.outbox.withOutboxTx(async(_t,e)=>{const r=(await e.query('SELECT * FROM bpc_pending WHERE token=$1',[token])).rows[0];return r?{registration:normalizeRegistration(r['registration']),requestedAt:reqInt({requestedAt:Number(r['requested_at'])},'requestedAt','pending')}:undefined;});}
  async listPending(){return this.outbox.withOutboxTx(async(_t,e)=>(await e.query('SELECT * FROM bpc_pending ORDER BY requested_at ASC')).rows.map(r=>({token:reqString({token:r['token']},'token','pending',256),registration:normalizeRegistration(r['registration']),requestedAt:reqInt({requestedAt:Number(r['requested_at'])},'requestedAt','pending')})));}
  async setPending(token:string,value:PairRegistration,requestedAt:number){if(!token||token.length>256||!Number.isSafeInteger(requestedAt)||requestedAt<0)throw new ContractValidationError('pending identity/time invalid');const registration=normalizeRegistration(value),aad={domain:'bpc-pair-payload' as const,version:'1' as const,streamId:this.opts.streamId,kind:'bpc.pending.set.v1' as const,token,requestedAt},sealed=this.codec.sealRegistration(registration,aad);await this.commit({kind:aad.kind,token,requestedAt,sealed},(e)=>upsertPending(e,token,registration,requestedAt));}
  async deletePending(token:string){if(!token||token.length>256)throw new ContractValidationError('token invalid');await this.commit({kind:'bpc.pending.delete.v1',token},async(e)=>affectedZeroOrOne(await e.query('DELETE FROM bpc_pending WHERE token=$1',[token]),'pending delete'));}
  async atomicMutate(pairId:string,mutate:PairAtomicMutation):Promise<StoredPair|undefined>{
    if(!ID.test(pairId)||typeof mutate!=='function')throw new ContractValidationError('atomic mutation input invalid');
    return this.outbox.withOutboxTx(async(tx,e)=>{
      const row=(await e.query('SELECT * FROM bpc_pairs WHERE id=$1',[pairId])).rows[0];
      if(!row)return undefined;
      const current=rowToPair(row),candidate=mutate(freezePair(current));
      if(candidate===undefined)return structuredClone(current);
      const next=normalizePair(candidate,false);
      if(next.id!==pairId)throw new ContractValidationError('atomic mutation cannot change pair identity');
      const aad={domain:'bpc-pair-payload' as const,version:'1' as const,streamId:this.opts.streamId,kind:'bpc.pair.set.v1' as const,pairId};
      const sealed=this.codec.sealPair(next,aad);
      await this.append(tx,e,{kind:aad.kind,pairId,sealed});
      await upsertPair(this.controlled(e),next);
      return rowToPair({...row,id:next.id,name:next.name,scope:next.scope,mode:next.mode,secret_hash:next.secretHash,pub_jwk:next.pubJwk,status:next.status,created:next.created,last_active:next.lastActive,requests:next.requests,failed_sigs:next.failedSigs,cumulative_failures:next.cumulativeFailures??null,first_failure_at:next.firstFailureAt??null,max_requests:next.maxRequests??null,kind:next.kind??'legitimate',canary_class:next.canaryClass??null,expires_at:next.expiresAt??null});
    });
  }
  async approvePending(token:string,expected:{registration:PairRegistration;requestedAt:number},pairValue:StoredPair,maxActivePairs:number):Promise<boolean>{
    if(!token||token.length>256||!Number.isSafeInteger(maxActivePairs)||maxActivePairs<1)throw new ContractValidationError('approval input invalid');
    const expectedRegistration=normalizeRegistration(expected.registration),pair=normalizePair(pairValue,false);
    assertApprovalPair(expectedRegistration,pair);
    if(!Number.isSafeInteger(expected.requestedAt)||expected.requestedAt<0)throw new ContractValidationError('pending time invalid');
    const pendingAad={domain:'bpc-pair-payload' as const,version:'1' as const,streamId:this.opts.streamId,kind:'bpc.pair.approve.v1' as const,token,requestedAt:expected.requestedAt};
    const pairAad={domain:'bpc-pair-payload' as const,version:'1' as const,streamId:this.opts.streamId,kind:'bpc.pair.approve.v1' as const,pairId:pair.id};
    const mutation:BpcPairMutation={kind:'bpc.pair.approve.v1',token,requestedAt:expected.requestedAt,expectedPending:this.codec.sealRegistration(expectedRegistration,pendingAad),pairId:pair.id,sealed:this.codec.sealPair(pair,pairAad)};
    return this.outbox.withOutboxTx(async(tx,e)=>{
      const row=(await e.query('SELECT registration,requested_at FROM bpc_pending WHERE token=$1',[token])).rows[0];
      if(!row)return false;
      if(Number(row['requested_at'])!==expected.requestedAt||!sameCanonical(normalizeRegistration(row['registration']),expectedRegistration))return false;
      const active=Number((await e.query("SELECT count(*)::text AS count FROM bpc_pairs WHERE status='active'")).rows[0]?.['count']);
      if(!Number.isSafeInteger(active)||active>=maxActivePairs)throw new ContractValidationError(`Maximum pair capacity (${maxActivePairs}) reached`);
      if((await e.query('SELECT 1 FROM bpc_pairs WHERE id=$1',[pair.id])).rows.length)throw new ContractValidationError('replacement pair identity already exists');
      await this.append(tx,e,mutation);
      affectedOne(await this.controlled(e).query('DELETE FROM bpc_pending WHERE token=$1 AND requested_at=$2',[token,expected.requestedAt]),'pending approval delete');
      await insertPair(this.controlled(e),pair);
      return true;
    });
  }
  async rotatePair(expectedOldValue:StoredPair,replacementValue:StoredPair):Promise<boolean>{
    const expectedOld=normalizePair(expectedOldValue,false),replacement=normalizePair(replacementValue,false);
    if(expectedOld.id===replacement.id)throw new ContractValidationError('rotation identities must differ');
    if(expectedOld.status!=='active'||!hasInitialPairState(replacement as StoredPair)||!rotationPolicyMatches(expectedOld as StoredPair,replacement as StoredPair))throw new ContractValidationError('rotation state/policy inheritance invalid');
    const oldAad={domain:'bpc-pair-payload' as const,version:'1' as const,streamId:this.opts.streamId,kind:'bpc.pair.rotate.v1' as const,pairId:expectedOld.id};
    const newAad={...oldAad,pairId:replacement.id};
    const mutation:BpcPairMutation={kind:'bpc.pair.rotate.v1',oldPairId:expectedOld.id,expectedOld:this.codec.sealPair(expectedOld,oldAad),newPairId:replacement.id,sealed:this.codec.sealPair(replacement,newAad)};
    return this.outbox.withOutboxTx(async(tx,e)=>{
      const row=(await e.query('SELECT * FROM bpc_pairs WHERE id=$1',[expectedOld.id])).rows[0];
      if(!row||!sameCanonical(normalizePair(rowToPair(row),false),expectedOld))return false;
      if(expectedOld.status!=='active'||(await e.query('SELECT 1 FROM bpc_pairs WHERE id=$1',[replacement.id])).rows.length)return false;
      await this.append(tx,e,mutation);
      const rotated={...expectedOld,status:'rotated' as const};await upsertPair(this.controlled(e),rotated);await insertPair(this.controlled(e),replacement);return true;
    });
  }
  async claimSuccessfulUse(pairId:string,at:number,expected:SuccessfulUsePolicy):Promise<SuccessfulUseClaim>{
    if(!ID.test(pairId)||!Number.isSafeInteger(at)||at<0)throw new ContractValidationError('successful-use claim input invalid');
    const captured={...structuredClone(expected),pubJwk:canonicalAuthorizationJwk(expected.pubJwk)};
    return this.outbox.withOutboxTx(async(tx,e)=>{
      const row=(await e.query('SELECT * FROM bpc_pairs WHERE id=$1',[pairId])).rows[0];
      if(!row)return 'missing';
      const current=rowToPair(row);
      if(current.status==='expired'){
        if(current.expiresAt!==undefined&&current.expiresAt<at)return 'time-expired';
        if(current.maxRequests&&current.maxRequests>0&&current.requests>=current.maxRequests)return 'usage-exhausted';
      }
      if(current.status!=='active')return 'inactive';
      if(current.expiresAt!==undefined&&current.expiresAt<at){
        const expired=normalizePair({...current,status:'expired'},false),aad={domain:'bpc-pair-payload' as const,version:'1' as const,streamId:this.opts.streamId,kind:'bpc.pair.set.v1' as const,pairId};
        await this.append(tx,e,{kind:aad.kind,pairId,sealed:this.codec.sealPair(expired,aad)});await upsertPair(this.controlled(e),expired);return 'time-expired';
      }
      if(current.maxRequests&&current.maxRequests>0&&current.requests>=current.maxRequests){
        const expired=normalizePair({...current,status:'expired'},false),aad={domain:'bpc-pair-payload' as const,version:'1' as const,streamId:this.opts.streamId,kind:'bpc.pair.set.v1' as const,pairId};
        await this.append(tx,e,{kind:aad.kind,pairId,sealed:this.codec.sealPair(expired,aad)});await upsertPair(this.controlled(e),expired);return 'usage-exhausted';
      }
      if(!successfulUsePolicyMatches(current,captured))return 'policy-changed';
      const requests=current.requests+1;
      if(!Number.isSafeInteger(requests))throw new ContractValidationError('pair request counter exhausted');
      const next=normalizePair({...current,requests,lastActive:at,failedSigs:0,cumulativeFailures:0,firstFailureAt:null,status:current.maxRequests&&current.maxRequests>0&&requests>=current.maxRequests?'expired':current.status},false);
      const aad={domain:'bpc-pair-payload' as const,version:'1' as const,streamId:this.opts.streamId,kind:'bpc.pair.set.v1' as const,pairId};
      await this.append(tx,e,{kind:aad.kind,pairId,sealed:this.codec.sealPair(next,aad)});await upsertPair(this.controlled(e),next);return 'claimed';
    });
  }
  async expireIfElapsed(pairId:string,now:number):Promise<boolean>{if(!Number.isSafeInteger(now)||now<0)throw new ContractValidationError('expiry check timestamp invalid');return this.conditionalStatus(pairId,(pair)=>pair.status==='active'&&pair.expiresAt!==undefined&&pair.expiresAt<now,'expired');}
  async expireIfUsageExhausted(pairId:string):Promise<boolean>{return this.conditionalStatus(pairId,(pair)=>pair.status==='active'&&!!pair.maxRequests&&pair.maxRequests>0&&pair.requests>=pair.maxRequests,'expired');}
  async lockIfFailureThreshold(pairId:string,minimumFailures:number):Promise<boolean>{if(!Number.isSafeInteger(minimumFailures)||minimumFailures<1)throw new ContractValidationError('failure threshold invalid');return this.conditionalStatus(pairId,(pair)=>pair.status==='active'&&pair.failedSigs>=minimumFailures,'locked');}
}

/** Package-internal HA factory. Deliberately omitted from the package entry
 * point; the public `createHaPairAuthority` validates the unforgeable fence
 * capability before reaching this constructor path. */
export function __internalCreateHaPairStore(db:PgTransactor,ready:SchemaReadyToken,opts:PgTransactionalPairStoreOptions,check:(exec:PgExecutor)=>Promise<void>,mutate?:ControlledMutation,append?:InternalHaFence[typeof HA_FENCE_INTERNAL]['append']):PgTransactionalPairStore{
  return new PgTransactionalPairStore(db,ready,opts,{[HA_FENCE_INTERNAL]:{check,mutate,append}});
}

export class PgPairMutationApplier implements MutationApplier<BpcPairMutation>{private readonly codec:Aes256GcmPairPayloadCodec;constructor(private readonly streamId:string,keyring:PairSealKeyring){if(!streamId||streamId.length>512)throw new ContractValidationError('streamId invalid');this.codec=new Aes256GcmPairPayloadCodec(keyring.activeKeyId,keyring.resolveKey);}async applyInTx(exec:PgExecutor,record:OutboxRecord<BpcPairMutation>){if(record.streamId!==this.streamId)throw new ContractValidationError('pair mutation stream mismatch');const m=normalizeMutation(record.mutation) as BpcPairMutation;switch(m.kind){case'bpc.pair.set.v1':await upsertPair(exec,this.codec.openPair(m.sealed,{domain:'bpc-pair-payload',version:'1',streamId:this.streamId,kind:m.kind,pairId:m.pairId}));return;case'bpc.pair.delete.v1':affectedZeroOrOne(await exec.query('DELETE FROM bpc_pairs WHERE id=$1',[m.pairId]),'pair delete');return;case'bpc.pending.set.v1':await upsertPending(exec,m.token,this.codec.openRegistration(m.sealed,{domain:'bpc-pair-payload',version:'1',streamId:this.streamId,kind:m.kind,token:m.token,requestedAt:m.requestedAt}),m.requestedAt);return;case'bpc.pending.delete.v1':affectedZeroOrOne(await exec.query('DELETE FROM bpc_pending WHERE token=$1',[m.token]),'pending delete');return;case'bpc.pair.approve.v1':{const pending=this.codec.openRegistration(m.expectedPending,{domain:'bpc-pair-payload',version:'1',streamId:this.streamId,kind:m.kind,token:m.token,requestedAt:m.requestedAt}),approved=this.codec.openPair(m.sealed,{domain:'bpc-pair-payload',version:'1',streamId:this.streamId,kind:m.kind,pairId:m.pairId});if(approved.id!==m.pairId)throw new ContractValidationError('replica approval envelope identity mismatch');assertApprovalPair(pending,approved);const row=(await exec.query('SELECT registration,requested_at FROM bpc_pending WHERE token=$1 FOR UPDATE',[m.token])).rows[0];if(!row||Number(row['requested_at'])!==m.requestedAt||!sameCanonical(normalizeRegistration(row['registration']),pending))throw new ContractValidationError('replica pending approval precondition failed');if((await exec.query('SELECT 1 FROM bpc_pairs WHERE id=$1',[m.pairId])).rows.length)throw new ContractValidationError('replica approval pair identity already exists');affectedOne(await exec.query('DELETE FROM bpc_pending WHERE token=$1 AND requested_at=$2',[m.token,m.requestedAt]),'replica pending approval delete');await insertPair(exec,approved);return;}case'bpc.pair.rotate.v1':{const expected=this.codec.openPair(m.expectedOld,{domain:'bpc-pair-payload',version:'1',streamId:this.streamId,kind:m.kind,pairId:m.oldPairId}),replacement=this.codec.openPair(m.sealed,{domain:'bpc-pair-payload',version:'1',streamId:this.streamId,kind:m.kind,pairId:m.newPairId});if(expected.id!==m.oldPairId||replacement.id!==m.newPairId||expected.status!=='active'||!hasInitialPairState(replacement as StoredPair)||!rotationPolicyMatches(expected as StoredPair,replacement as StoredPair))throw new ContractValidationError('replica rotation identity/state/policy inheritance failed');const row=(await exec.query('SELECT * FROM bpc_pairs WHERE id=$1 FOR UPDATE',[m.oldPairId])).rows[0];if(!row||!sameCanonical(normalizePair(rowToPair(row),false),expected))throw new ContractValidationError('replica rotation precondition failed');if((await exec.query('SELECT 1 FROM bpc_pairs WHERE id=$1',[m.newPairId])).rows.length)throw new ContractValidationError('replica rotation pair identity already exists');await upsertPair(exec,{...expected,status:'rotated'});await insertPair(exec,replacement);return;}}}}
