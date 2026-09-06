import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

export const WORKSPACES = [
  'packages/core',
  'packages/server',
  'packages/client-sdk',
];

export function runWorkspaceTests(
  args,
  spawn = spawnSync,
  npmExecPath = process.env.npm_execpath,
) {
  if (!npmExecPath) {
    throw new Error('npm_execpath is required to run workspace tests');
  }
  for (const workspace of WORKSPACES) {
    const commandArgs = [npmExecPath, 'run', 'test', `--workspace=${workspace}`];
    if (args.length > 0) {
      commandArgs.push('--', ...args);
    }
    const result = spawn(process.execPath, commandArgs, { stdio: 'inherit' });
    if (result.error) {
      throw result.error;
    }
    if (result.status !== 0) {
      return result.status ?? 1;
    }
  }
  return 0;
}

export function main(args = process.argv.slice(2)) {
  process.exitCode = runWorkspaceTests(args);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
