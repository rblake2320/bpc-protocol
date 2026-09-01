/**
 * Proves that the npm artifacts, rather than workspace source paths, can sign
 * and verify a request in a clean temporary consumer project.
 */
import { execFileSync } from 'node:child_process';
import { mkdir, mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const root = resolve('.');
const consumer = await mkdtemp(join(tmpdir(), 'bpc-installed-'));
const artifacts = join(consumer, 'artifacts');

function npm(...args: string[]): string {
  const npmCli = process.env['npm_execpath'];
  if (!npmCli) throw new Error('npm_execpath is required to run the artifact smoke test');
  return execFileSync(process.execPath, [npmCli, ...args], {
    cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'],
  });
}

try {
  npm('run', 'build');
  await mkdir(artifacts);
  for (const workspace of ['packages/core', 'packages/server', 'packages/client-sdk']) {
    npm('pack', '--workspace', workspace, '--pack-destination', artifacts);
  }

  const archive = async (prefix: string): Promise<string> => {
    const name = (await readdir(artifacts)).find(item => item.startsWith(prefix) && item.endsWith('.tgz'));
    if (!name) throw new Error(`npm pack did not create an archive for ${prefix}`);
    return join(artifacts, name).replace(/\\/g, '/');
  };
  const core = await archive('bpc-core-');
  const server = await archive('bpc-server-');
  const client = await archive('bpc-client-sdk-');
  await writeFile(join(consumer, 'package.json'), JSON.stringify({
    private: true,
    type: 'module',
    dependencies: {
      '@bpc/core': `file:${core}`,
      '@bpc/server': `file:${server}`,
      '@bpc/client-sdk': `file:${client}`,
    },
  }, null, 2));
  const npmCli = process.env['npm_execpath'];
  if (!npmCli) throw new Error('npm_execpath is required to install the temporary consumer');
  execFileSync(process.execPath, [npmCli, 'install', '--no-audit', '--no-fund'], {
    cwd: consumer, stdio: 'inherit',
  });

  await writeFile(join(consumer, 'smoke.mjs'), `
    import { generateKeypair, hashSecret } from '@bpc/core';
    import { createBPCServer, verifyBPCRequest } from '@bpc/server';
    import { BPCClient } from '@bpc/client-sdk';
    const keypair = await generateKeypair();
    const secret = 'installed-artifact-smoke-secret-2026';
    const server = createBPCServer();
    const pairId = await server.registry.registerDirect({
      name: 'installed-artifact-smoke', scope: 'read', mode: 'development',
      secretHash: await hashSecret(secret), pubJwk: keypair.pubJwk,
    });
    const client = new BPCClient({ serverUrl: 'http://127.0.0.1', pairId, keypair, secret });
    const headers = await client.signRequest('GET', '/installed-smoke');
    const result = await verifyBPCRequest({
      pairId: headers['X-BPC-Pair-ID'], signedData: headers['X-BPC-Signed-Data'],
      signature: headers['X-BPC-Signature'], version: headers['X-BPC-Version'],
      method: 'GET', path: '/installed-smoke',
      bodyHash: 'sha256:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU', ip: '127.0.0.1',
    }, server.registry, server.nonceStore, server.anomaly, { sigWindowMs: 60_000, enableTarpit: false });
    if (!result.ok) throw new Error('installed artifacts rejected a valid request: ' + result.error);
  `);
  execFileSync(process.execPath, ['smoke.mjs'], { cwd: consumer, stdio: 'inherit' });
  console.log('Installed npm artifact smoke: PASS (clean consumer signed and verified a request)');
} finally {
  await rm(consumer, { recursive: true, force: true });
}
