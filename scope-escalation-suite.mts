/**
 * BPC Protocol — Scope Escalation Attack Suite
 *
 * Tests that scope enforcement correctly constrains HTTP methods per pair.
 * Attacks mirror what a compromised read-only credential could attempt.
 *
 * Run directly against a started demo server, or use `npm run test:adversarial`
 * to start an isolated server and execute every adversarial suite.
 */

import { prepareRegistration, BPCClient } from './packages/client-sdk/src/index.ts';
import { generateKeypair } from './packages/core/src/index.ts';

const SERVER = process.env['BPC_TEST_SERVER_URL'] ?? 'http://127.0.0.1:3100';
const ADMIN_TOKEN = process.env['BPC_TEST_ADMIN_TOKEN'] ?? 'demo-admin-token-change-before-use-32';
const TEST_SECRET = 'BPC-Test-Secret-2026!';
let pass = 0, fail = 0;

function result(name: string, ok: boolean, detail = '') {
  const tag = ok ? 'PASS' : 'FAIL';
  if (ok) pass++; else fail++;
  console.log(`  [${tag}] ${name}${detail ? ' -- ' + detail : ''}`);
}

async function register(name: string, scope: 'read' | 'read-write' | 'admin', secret = TEST_SECRET) {
  const { keypair, request } = await prepareRegistration(name, secret, scope, 'development');
  const r = await fetch(`${SERVER}/bpc/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
  });
  if (!r.ok) throw new Error(`Registration failed: ${r.status}`);
  const b = await r.json() as { pairId: string };
  return new BPCClient({ pairId: b.pairId, keypair, secret, serverUrl: SERVER });
}

// ── ATTACK 1: read pair → write methods ──────────────────────────────────────
console.log('\n== ATTACK 1: read-scoped pair attempting write methods ==');
{
  const c = await register('read-only-client', 'read');

  for (const method of ['POST', 'PUT', 'PATCH']) {
    const r = await c.fetch(`/api/data`, { method, body: '{}' });
    result(
      `read pair → ${method} /api/data => scope_violation`,
      r.status === 403 && (await r.json() as any)['error'] === 'scope_violation',
      `status=${r.status}`,
    );
  }

  const rDelete = await c.fetch('/api/data', { method: 'DELETE' });
  result(
    'read pair → DELETE => scope_violation',
    rDelete.status === 403 && (await rDelete.json() as any)['error'] === 'scope_violation',
    `status=${rDelete.status}`,
  );

  // Read methods must still work
  const rGet = await c.fetch('/api/status', { method: 'GET' });
  result(
    'read pair → GET still allowed',
    rGet.status !== 403,
    `status=${rGet.status}`,
  );
}

// ── ATTACK 2: read-write pair → DELETE ───────────────────────────────────────
console.log('\n== ATTACK 2: read-write pair attempting DELETE ==');
{
  const c = await register('rw-client', 'read-write');

  const r = await c.fetch('/api/resource/42', { method: 'DELETE' });
  result(
    'read-write pair → DELETE => scope_violation',
    r.status === 403 && (await r.json() as any)['error'] === 'scope_violation',
    `status=${r.status}`,
  );

  // POST/PUT/PATCH must be allowed
  for (const method of ['POST', 'PUT', 'PATCH']) {
    const r2 = await c.fetch('/api/data', { method, body: '{}' });
    result(
      `read-write pair → ${method} still allowed`,
      r2.status !== 403,
      `status=${r2.status}`,
    );
  }
}

// ── ATTACK 3: admin pair has full access ─────────────────────────────────────
console.log('\n== ATTACK 3: admin pair scope baseline ==');
{
  const c = await register('admin-client', 'admin');

  for (const method of ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']) {
    const r = await c.fetch('/api/data', { method, body: method !== 'GET' ? '{}' : undefined });
    result(
      `admin pair → ${method} not scope_violation`,
      (await r.json() as any)['error'] !== 'scope_violation',
      `status=${r.status}`,
    );
  }
}

// ── ATTACK 4: payload method/scope mismatch (cross-sign) ─────────────────────
// Attacker has a read pair; signs a GET payload; sends it as POST.
// Expected: method_path_mismatch (step 9) before scope check (step 10).
console.log('\n== ATTACK 4: signed GET payload replayed as POST ==');
{
  const c = await register('replay-cross-client', 'read');

  // Capture a valid signed GET request blob
  const signedGetHeaders = await c.signRequest('GET', '/api/data', undefined);

  // Replay the same signed headers on a POST request
  const r = await fetch(`${SERVER}/api/data`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...signedGetHeaders,
    },
    body: '{}',
  });
  const body = await r.json() as any;
  result(
    'GET payload replayed as POST => method_path_mismatch',
    r.status === 400 && body['error'] === 'method_path_mismatch',
    `status=${r.status} error=${body['error']}`,
  );
}

// ── ATTACK 5: scope preserved across rotation ─────────────────────────────────
// Rotate a read pair; verify the new pair is still read-scoped.
console.log('\n== ATTACK 5: scope cannot be escalated via key rotation ==');
{
  const c = await register('rotate-scope-client', 'read');

  const newKeypair = await generateKeypair();
  const { newPairId } = await c.rotate(newKeypair.pubJwk);
  const rotated = new BPCClient({
    pairId: newPairId,
    keypair: newKeypair,
    secret: TEST_SECRET,
    serverUrl: SERVER,
  });

  // Attempt write with new pair ID
  const r = await rotated.fetch('/api/data', { method: 'POST', body: '{}' });
  result(
    'rotated read pair still cannot POST => scope_violation',
    r.status === 403 && (await r.json() as any)['error'] === 'scope_violation',
    `status=${r.status}`,
  );
}

// ── ATTACK 6: unknown scope rejected at the network boundary ─────────────────
console.log('\n== ATTACK 6: unknown scope rejected during registration ==');
{
  const { request } = await prepareRegistration(
    'invalid-scope-client', TEST_SECRET, 'read', 'development',
  );
  const r = await fetch(`${SERVER}/bpc/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...request, scope: 'superuser' }),
  });
  const body = await r.json() as Record<string, unknown>;
  result(
    'scope="superuser" registration => invalid_registration',
    r.status === 400 && body['error'] === 'invalid_registration',
    `status=${r.status} error=${body['error']}`,
  );
}

// ── ATTACK 7: scope denial increments anomaly counter ────────────────────────
console.log('\n== ATTACK 7: scope denials feed anomaly engine ==');
{
  const c = await register('anomaly-scope-client', 'read');
  const adminHeaders = { Authorization: `Bearer ${ADMIN_TOKEN}` };
  const beforeResponse = await fetch(`${SERVER}/bpc/anomaly`, { headers: adminHeaders });
  if (!beforeResponse.ok) throw new Error(`Admin anomaly baseline failed: ${beforeResponse.status}`);
  const before = await beforeResponse.json() as {
    counters: { deniedRequests: number };
  };

  for (let i = 0; i < 5; i++) {
    await c.fetch('/api/data', { method: 'DELETE' });
  }

  const r = await fetch(`${SERVER}/bpc/anomaly`, { headers: adminHeaders });
  if (!r.ok) throw new Error(`Admin anomaly verification failed: ${r.status}`);
  const after = await r.json() as { counters: { deniedRequests: number } };
  const delta = after.counters.deniedRequests - before.counters.deniedRequests;
  result(
    '5 scope denials increment denied-request evidence by 5',
    delta === 5,
    `denied_delta=${delta}`,
  );
}

// ── Summary ───────────────────────────────────────────────────────────────────
console.log(`\n── Scope Escalation Suite ──  PASS: ${pass}  FAIL: ${fail} ──`);
if (fail > 0) process.exit(1);
