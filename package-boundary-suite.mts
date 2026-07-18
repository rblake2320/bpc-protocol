import { access, readFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

interface PackageManifest {
  name: string;
  version: string;
  main: string;
  types: string;
  files?: string[];
  dependencies?: Record<string, string>;
  exports?: { '.': { import?: string; types?: string } };
}

const workspaces = ['core', 'server', 'client-sdk'];
let passed = 0;
function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

for (const workspace of workspaces) {
  const packageDir = path.resolve('packages', workspace);
  const manifest = JSON.parse(await readFile(path.join(packageDir, 'package.json'), 'utf8')) as PackageManifest;
  assert(manifest.files?.includes('dist'), `${manifest.name} does not publish dist`);
  assert(manifest.exports?.['.']?.import === manifest.main, `${manifest.name} import export disagrees with main`);
  assert(manifest.exports?.['.']?.types === manifest.types, `${manifest.name} type export disagrees with types`);
  for (const [dependency, range] of Object.entries(manifest.dependencies ?? {})) {
    if (dependency.startsWith('@bpc/')) assert(range === `^${manifest.version}`, `${manifest.name} has unbounded internal dependency ${dependency}@${range}`);
  }
  const mainPath = path.resolve(packageDir, manifest.main);
  const typesPath = path.resolve(packageDir, manifest.types);
  await access(mainPath); await access(typesPath);
  const runtime = await import(pathToFileURL(mainPath).href);
  assert(Object.keys(runtime).length > 0, `${manifest.name} runtime entry point has no exports`);
  if (manifest.name === '@bpc/server') {
    const direct = await import(pathToFileURL(path.resolve(packageDir, 'dist/ha-outbox-pg.js')).href);
    const names = [...Object.keys(runtime), ...Object.keys(direct)];
    assert(!names.some((name) => /unsafe.*mint|mint.*ready.*test/i.test(name)), '@bpc/server publishes a readiness-token bypass');
    assert(!('MemoryReplayNonceStore' in runtime) && !('createMemoryReplayNonceStoreForTests' in runtime),
      '@bpc/server publishes a non-durable replay authority');
  }
  passed++;
  console.log(`  PASS ${manifest.name} entry points exist and import`);
}
console.log(`BPC package boundary suite: ${passed}/${workspaces.length} passed`);
