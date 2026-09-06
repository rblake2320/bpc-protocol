// Exercise published tarballs in an isolated consumer, never workspace imports.
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';

const root = resolve(import.meta.dirname, '..');
const evidence = mkdtempSync(join(tmpdir(), 'bpc-installed-file-store-'));
const packages = join(evidence, 'packages');
const consumer = join(evidence, 'consumer');
mkdirSync(packages); mkdirSync(consumer);
const receipt = { ok: false, evidence, commands: [], artifacts: [] };
function run(command, args, cwd) {
  const result = spawnSync(command, args, { cwd, encoding: 'utf8', timeout: 120000 });
  receipt.commands.push({ command, args, cwd, status: result.status, stdout: result.stdout, stderr: result.stderr });
  if (result.error || result.status !== 0) throw Error(`Child failed: ${command}: ${result.error ?? result.stderr}`);
  return result.stdout;
}
function npm(args, cwd) {
  if (!process.env.npm_execpath) throw Error('Run using npm run test:installed-file-store');
  return run(process.execPath, [process.env.npm_execpath, ...args], cwd);
}
try {
  for (const name of ['core', 'server']) {
    const packed = JSON.parse(npm(['pack', `./packages/${name}`, '--ignore-scripts', '--json', '--pack-destination', packages], root));
    if (packed.length !== 1) throw Error(`Expected one ${name} tarball`);
    const file = join(packages, packed[0].filename);
    receipt.artifacts.push({ name, file, sha256: createHash('sha256').update(readFileSync(file)).digest('hex') });
  }
  writeFileSync(join(consumer, 'package.json'), JSON.stringify({ private: true, type: 'module' }));
  npm(['install', '--ignore-scripts', '--omit=optional', '--no-audit', ...receipt.artifacts.map(x => x.file)], consumer);
  const probe = `import assert from 'node:assert/strict';
import { writeFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { FileNonceBackend, FileAnomalyStore, FilePairStore } from '@bpc/server';
const root=process.cwd(), checks=[];
const nonce=join(root,'nonce.json');
assert.equal(await new FileNonceBackend(nonce).checkAndConsume('installed-once',60000),false);
assert.equal(await new FileNonceBackend(nonce).checkAndConsume('installed-once',60000),true); checks.push('nonce replay survives new instance');
const anomaly=join(root,'anomaly.json');
await new FileAnomalyStore(anomaly).increment('test');
assert.equal(await new FileAnomalyStore(anomaly).increment('test'),2); checks.push('anomaly count survives new instance');
writeFileSync(nonce,'{"seen":null}'); const before=readFileSync(nonce);
await assert.rejects(new FileNonceBackend(nonce).checkAndConsume('seen',60000),/BPC_FILE_STORE_CORRUPT/);
assert.deepEqual(readFileSync(nonce),before); checks.push('corrupt nonce refused with bytes unchanged');
const pairs=join(root,'pairs.json'); writeFileSync(pairs,'{"pairs":{"bad":null},"pending":{}}');
await assert.rejects(new FilePairStore(pairs).list(),/BPC_FILE_STORE_CORRUPT/); checks.push('corrupt pair refused');
writeFileSync(join(root,'result.json'),JSON.stringify({ok:true,checks}));`;
  writeFileSync(join(consumer, 'probe.mjs'), probe);
  run(process.execPath, ['probe.mjs'], consumer);
  receipt.result = JSON.parse(readFileSync(join(consumer, 'result.json'), 'utf8'));
  if (receipt.result.ok !== true || receipt.result.checks.length !== 4) throw Error('Missing installed result');
  receipt.ok = true;
} catch (error) {
  receipt.error = String(error); process.exitCode = 1;
} finally {
  writeFileSync(join(evidence, 'receipt.json'), JSON.stringify(receipt, null, 2));
  console.log(JSON.stringify({ ok: receipt.ok, receipt: join(evidence, 'receipt.json'), error: receipt.error }));
}
