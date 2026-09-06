/** Strict local-file persistence for BPC. Single host only; no stale-lock stealing. */
import { closeSync, existsSync, fstatSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import type { PairStore, NonceStoreBackend, AnomalyStore } from './store.js';
import type { StoredPair, PairRegistration } from './types.js';

interface FileStoreData { pairs: Record<string, StoredPair>; pending: Record<string, { registration: PairRegistration; requestedAt: number }>; }
interface NonceEntry { expiresAt: number; }
interface AnomalyEntry { value: number; expiresAt: number; }
type Obj=Record<string,unknown>;
const obj=(v:unknown):v is Obj=>v!==null&&typeof v==='object'&&!Array.isArray(v);
function corrupt(path:string):never{throw new Error(`BPC_FILE_STORE_CORRUPT:${path}`);}
function read(path:string):Obj{try{const stat=lstatSync(path);if(!stat.isFile()||stat.isSymbolicLink()||stat.nlink!==1)corrupt(path);const v:unknown=JSON.parse(readFileSync(path,'utf8'));if(!obj(v))corrupt(path);return v;}catch(e){if(e instanceof Error&&e.message.startsWith('BPC_FILE_STORE_CORRUPT:'))throw e;corrupt(path);}}

abstract class AtomicFile<T>{
 protected readonly path:string;
 constructor(path:string){this.path=resolve(path);mkdirSync(dirname(this.path),{recursive:true});}
 protected abstract empty():T; protected abstract decode(v:Obj):T;
 private load():T{return existsSync(this.path)?this.decode(read(this.path)):this.empty();}
 private save(v:T){const tmp=`${this.path}.${process.pid}.${randomUUID()}.tmp`;let fd:number|undefined;try{fd=openSync(tmp,'wx',0o600);writeFileSync(fd,JSON.stringify(v,null,2),'utf8');fsyncSync(fd);closeSync(fd);fd=undefined;renameSync(tmp,this.path);}catch(e){if(fd!==undefined)try{closeSync(fd);}catch{} if(existsSync(tmp))try{unlinkSync(tmp);}catch{} throw new Error(`BPC_FILE_STORE_WRITE_FAILED:${this.path}`,{cause:e});}}
 protected tx<R>(fn:(current:T)=>{next?:T,result:R}):R{const lock=`${this.path}.lock`;let fd:number;try{fd=openSync(lock,'wx',0o600);}catch{throw new Error(`BPC_FILE_STORE_LOCK_UNAVAILABLE:${lock}; resolve owner before retry`);}const id=fstatSync(fd,{bigint:true});try{writeFileSync(fd,JSON.stringify({pid:process.pid,owner:randomUUID(),createdAt:Date.now()}));fsyncSync(fd);const out=fn(this.load());if(out.next!==undefined)this.save(out.next);return out.result;}finally{closeSync(fd);try{const now=lstatSync(lock,{bigint:true});if(now.dev!==id.dev||now.ino!==id.ino)throw new Error(`BPC_FILE_STORE_LOCK_CHANGED:${lock}; operation outcome unknown`);unlinkSync(lock);}catch(e){if(e instanceof Error&&e.message.startsWith('BPC_FILE_STORE_LOCK_CHANGED:'))throw e;throw new Error(`BPC_FILE_STORE_LOCK_RELEASE_FAILED:${lock}`,{cause:e});}}}
}

export class FilePairStore extends AtomicFile<FileStoreData> implements PairStore{
 protected empty(){return{pairs:{},pending:{}};} protected decode(v:Obj){if(!obj(v.pairs)||!obj(v.pending))corrupt(this.path);return{pairs:structuredClone(v.pairs) as Record<string,StoredPair>,pending:structuredClone(v.pending) as FileStoreData['pending']};}
 async get(id:string){return this.tx(d=>({result:d.pairs[id]?structuredClone(d.pairs[id]):undefined}));}
 async set(pair:StoredPair){this.tx(d=>{const n=structuredClone(d);n.pairs[pair.id]=structuredClone(pair);return{next:n,result:undefined};});}
 async delete(id:string){this.tx(d=>{const n=structuredClone(d);delete n.pairs[id];return{next:n,result:undefined};});}
 async list(){return this.tx(d=>({result:Object.values(d.pairs).map(x=>structuredClone(x))}));}
 async getPending(token:string){return this.tx(d=>({result:d.pending[token]?structuredClone(d.pending[token]):undefined}));}
 async setPending(token:string,registration:PairRegistration,requestedAt:number){this.tx(d=>{const n=structuredClone(d);n.pending[token]={registration:structuredClone(registration),requestedAt};return{next:n,result:undefined};});}
 async deletePending(token:string){this.tx(d=>{const n=structuredClone(d);delete n.pending[token];return{next:n,result:undefined};});}
 async listPending(){return this.tx(d=>({result:Object.entries(d.pending).map(([token,value])=>({token,...structuredClone(value)}))}));}
}

export class FileNonceBackend extends AtomicFile<Record<string,NonceEntry>> implements NonceStoreBackend{
 protected empty(){return{};} protected decode(v:Obj){for(const x of Object.values(v))if(!obj(x)||!Number.isSafeInteger(x['expiresAt'])||(x['expiresAt'] as number)<0)corrupt(this.path);return structuredClone(v) as Record<string,NonceEntry>;}
 async checkAndConsume(nonce:string,ttlMs:number){if(!nonce||!Number.isSafeInteger(ttlMs)||ttlMs<1)throw new Error('BPC_FILE_NONCE_INPUT_INVALID');return this.tx(d=>{const now=Date.now(),n=structuredClone(d);for(const[k,v]of Object.entries(n))if(v.expiresAt<=now)delete n[k];const replay=n[nonce]?.expiresAt>now;if(!replay)n[nonce]={expiresAt:now+ttlMs};return{next:n,result:replay};});}
}

export class FileAnomalyStore extends AtomicFile<Record<string,AnomalyEntry>> implements AnomalyStore{
 protected empty(){return{};} protected decode(v:Obj){for(const x of Object.values(v))if(!obj(x)||!Number.isSafeInteger(x['value'])||(x['value'] as number)<0||!Number.isSafeInteger(x['expiresAt'])||(x['expiresAt'] as number)<0)corrupt(this.path);return structuredClone(v) as Record<string,AnomalyEntry>;}
 async increment(key:string,ttlMs=3600000){if(!key||!Number.isSafeInteger(ttlMs)||ttlMs<1)throw new Error('BPC_FILE_ANOMALY_INPUT_INVALID');return this.tx(d=>{const now=Date.now(),n=structuredClone(d);for(const[k,v]of Object.entries(n))if(v.expiresAt<=now)delete n[k];const value=(n[key]?.expiresAt>now?n[key].value:0)+1;n[key]={value,expiresAt:now+ttlMs};return{next:n,result:value};});}
 async get(key:string){return this.tx(d=>{const v=d[key];return{result:v&&v.expiresAt>Date.now()?v.value:0};});}
 async reset(key:string){this.tx(d=>{const n=structuredClone(d);delete n[key];return{next:n,result:undefined};});}
}
