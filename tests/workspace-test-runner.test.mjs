import assert from 'node:assert/strict';
import test from 'node:test';

import {
  WORKSPACES,
  runWorkspaceTests,
} from '../scripts/run-workspace-tests.mjs';

test('forwards root test arguments to every workspace', () => {
  const calls = [];
  const status = runWorkspaceTests(
    ['--coverage', '--reporter=dot'],
    (...args) => {
      calls.push(args);
      return { status: 0 };
    },
    '/npm/npm-cli.js',
  );

  assert.equal(status, 0);
  assert.equal(calls.length, WORKSPACES.length);
  for (const [index, call] of calls.entries()) {
    assert.deepEqual(call[1], [
      '/npm/npm-cli.js',
      'run',
      'test',
      `--workspace=${WORKSPACES[index]}`,
      '--',
      '--coverage',
      '--reporter=dot',
    ]);
    assert.deepEqual(call[2], { stdio: 'inherit' });
  }
});

test('stops at the first failed workspace', () => {
  const calls = [];
  const status = runWorkspaceTests(
    [],
    (...args) => {
      calls.push(args);
      return { status: calls.length === 2 ? 17 : 0 };
    },
    '/npm/npm-cli.js',
  );

  assert.equal(status, 17);
  assert.equal(calls.length, 2);
  assert.match(calls[0][1][3], /packages\/core/);
  assert.match(calls[1][1][3], /packages\/server/);
});

test('throws when the npm process cannot be started', () => {
  const failure = new Error('npm unavailable');
  assert.throws(
    () => runWorkspaceTests(
      [],
      () => ({ status: null, error: failure }),
      '/npm/npm-cli.js',
    ),
    failure,
  );
});

test('fails closed when the npm executable path is unavailable', () => {
  assert.throws(
    () => runWorkspaceTests([], () => ({ status: 0 }), ''),
    /npm_execpath is required/,
  );
});
