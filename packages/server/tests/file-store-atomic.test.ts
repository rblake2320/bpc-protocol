import { mkdtempSync, writeFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';
import { FileAnomalyStore, FileNonceBackend, FilePairStore } from '../src/file-store.js';

describe('atomic BPC file stores', () => {
  it('rejects corrupt persisted authority instead of treating it as empty', () => {
    const path=join(mkdtempSync(join(tmpdir(),'bpc-file-')),'pairs.json'); writeFileSync(path,'{truncated');
    expect(()=>new FilePairStore(path)).not.toThrow();
    return expect(new FilePairStore(path).list()).rejects.toThrow(/BPC_FILE_STORE_CORRUPT/);
  });
  it('rejects A2 inner-null nonce and malformed anomaly entries without reset', async () => {
    const dir=mkdtempSync(join(tmpdir(),'bpc-file-')); const nonce=join(dir,'nonces.json'), anomaly=join(dir,'anomaly.json');
    writeFileSync(nonce,'{"synthetic-seen-nonce":null}'); writeFileSync(anomaly,'{"attack":{"value":null,"expiresAt":1}}');
    await expect(new FileNonceBackend(nonce).checkAndConsume('synthetic-seen-nonce',60000)).rejects.toThrow(/BPC_FILE_STORE_CORRUPT/);
    await expect(new FileAnomalyStore(anomaly).increment('attack')).rejects.toThrow(/BPC_FILE_STORE_CORRUPT/);
  });
  it('rejects prototype keys and unsafe expiry candidates before publication', async () => {
    const dir=mkdtempSync(join(tmpdir(),'bpc-file-')); const nonce=join(dir,'nonces.json'), anomaly=join(dir,'anomaly.json');
    await expect(new FileNonceBackend(nonce).checkAndConsume('__proto__',60000)).rejects.toThrow(/BPC_FILE_NONCE_INPUT_INVALID/);
    await expect(new FileAnomalyStore(anomaly).increment('__proto__')).rejects.toThrow(/BPC_FILE_ANOMALY_INPUT_INVALID/);
    await expect(new FileNonceBackend(nonce).checkAndConsume('safe',Number.MAX_SAFE_INTEGER)).rejects.toThrow(/BPC_FILE_NONCE_INPUT_INVALID/);
    expect(() => new FileNonceBackend(nonce)).not.toThrow();
  });
  it('rejects incomplete persisted pair authority', async () => {
    const path=join(mkdtempSync(join(tmpdir(),'bpc-file-')),'pairs.json'); writeFileSync(path,'{"pairs":{"synthetic":null},"pending":{}}');
    await expect(new FilePairStore(path).list()).rejects.toThrow(/BPC_FILE_STORE_CORRUPT/);
  });
  it('serializes fresh nonce reads across independent store instances', async () => {
    const path=join(mkdtempSync(join(tmpdir(),'bpc-file-')),'nonces.json'); const a=new FileNonceBackend(path),b=new FileNonceBackend(path);
    const result=await Promise.all([a.checkAndConsume('same',60000),b.checkAndConsume('same',60000)]);
    expect(result.sort()).toEqual([false,true]);
  });
  it('serializes a nonce race across two child processes', async () => {
    const path=join(mkdtempSync(join(tmpdir(),'bpc-file-')),'nonces.json'); const child=join(import.meta.dirname,'file-store-atomic-child.mts');
    const run=()=>new Promise<{replay?:boolean,error?:string}>((resolve,reject)=>{const loader=createRequire(import.meta.url).resolve('tsx');const p=spawn(process.execPath,['--import',pathToFileURL(loader).href,child,path,'cross-process'],{cwd:process.cwd(),stdio:['ignore','pipe','pipe']});let out='',err='';p.stdout.on('data',x=>out+=x);p.stderr.on('data',x=>err+=x);p.on('error',reject);p.on('close',code=>code===0?resolve(JSON.parse(out)):reject(new Error(err)));});
    const results=await Promise.all([run(),run()]); expect(results.some(x=>x.replay===false)).toBe(true); expect(results.some(x=>x.replay===true||x.error==='BPC_FILE_STORE_LOCK_UNAVAILABLE')).toBe(true);
    expect((await run()).replay).toBe(true);
  });
  it('does not lose anomaly increments across independent store instances', async () => {
    const path=join(mkdtempSync(join(tmpdir(),'bpc-file-')),'anomaly.json'); const a=new FileAnomalyStore(path),b=new FileAnomalyStore(path);
    await a.increment('attack'); await b.increment('attack'); expect(await new FileAnomalyStore(path).get('attack')).toBe(2);
  });
});


