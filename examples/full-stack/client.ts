import { BPCClient, prepareRegistration } from '../../packages/client-sdk/src/index.ts';
import { generateNonce, generateId, BPC_PROTOCOL_VERSION, generateKeypair } from '../../packages/core/src/index.ts';

const SERVER = 'http://localhost:3100';
const SECRET = 'Demo-secret-' + Date.now() + '!@';
const DEVICE_NAME = 'e2e-test-client';

function label(name: string, ok: boolean, detail?: string): void {
  const tag = ok ? 'PASS' : 'FAIL';
  const extra = detail ? ` -- ${detail}` : '';
  console.log(`  [${tag}] ${name}${extra}`);
}

async function main(): Promise<void> {
  console.log('=== BPC Full-Stack End-to-End Test ===\n');
  console.log(`Protocol version: ${BPC_PROTOCOL_VERSION}\n`);

  // --- Step 1: Register ---
  console.log('1. Registering new pair...');
  const { keypair, request } = await prepareRegistration(DEVICE_NAME, SECRET, 'read-write', 'development');

  const regRes = await fetch(`${SERVER}/bpc/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(request),
  });
  const regBody = await regRes.json() as { pairId: string; status: string };
  label('Registration', regRes.ok && regBody.pairId != null, `pair=${regBody.pairId}`);

  if (!regBody.pairId) {
    console.error('Registration failed, aborting.');
    process.exit(1);
  }

  // --- Step 2: Create BPCClient ---
  const client = new BPCClient({
    serverUrl: SERVER,
    pairId: regBody.pairId,
    keypair,
    secret: SECRET,
  });

  // --- Step 3: Three signed requests to /api/status ---
  console.log('\n2. Sending 3 signed requests to /api/status...');

  for (let i = 1; i <= 3; i++) {
    const res = await client.fetch('/api/status');
    const body = await res.json() as Record<string, unknown>;
    const ok = res.status === 200 && body.status === 'ok';
    label(`GET /api/status (${i}/3)`, ok, `status=${res.status} scope=${body.scope}`);
  }

  // --- Step 4: One signed request to /api/users ---
  console.log('\n3. Sending signed request to /api/users...');
  const usersRes = await client.fetch('/api/users');
  const usersBody = await usersRes.json() as Record<string, unknown>;
  const usersOk = usersRes.status === 200 && Array.isArray(usersBody.users);
  label('GET /api/users', usersOk, `users=${JSON.stringify(usersBody.users)}`);

  // --- Step 5: Replay attack ---
  console.log('\n4. Attempting replay attack (reusing old headers)...');

  // Make a legitimate request and capture the headers
  const replayHeaders = await client.signRequest('GET', '/api/status');
  label('X-BPC-Version in headers', replayHeaders['X-BPC-Version'] === BPC_PROTOCOL_VERSION, `version=${replayHeaders['X-BPC-Version']}`);

  // Use these headers once (legitimate)
  const legitRes = await fetch(`${SERVER}/api/status`, {
    method: 'GET',
    headers: replayHeaders as unknown as Record<string, string>,
  });
  const legitOk = legitRes.status === 200;
  label('Legitimate request (sets nonce)', legitOk, `status=${legitRes.status}`);

  // Now replay the exact same headers -- should be rejected
  const replayRes = await fetch(`${SERVER}/api/status`, {
    method: 'GET',
    headers: replayHeaders as unknown as Record<string, string>,
  });
  const replayBody = await replayRes.json() as Record<string, unknown>;
  const replayBlocked = replayRes.status === 401 && replayBody.error === 'replay_detected';
  label('Replay attempt', replayBlocked, `status=${replayRes.status} error=${replayBody.error}`);

  // --- Step 6: Scope enforcement ---
  console.log('\n5. Testing scope enforcement (DELETE on read-write pair)...');
  const scopeHeaders = await client.signRequest('DELETE', '/api/admin');
  const scopeRes = await fetch(`${SERVER}/api/admin`, {
    method: 'DELETE',
    headers: scopeHeaders as unknown as Record<string, string>,
  });
  const scopeBody = await scopeRes.json() as Record<string, unknown>;
  label('Scope violation (DELETE rejected for read-write)', scopeRes.status === 403 && scopeBody.error === 'scope_violation', `status=${scopeRes.status} error=${scopeBody.error}`);

  // --- Step 7: Unknown pair ID ---
  console.log('\n6. Unknown pair ID...');

  // Sign a request but tamper with the pair ID header
  const fakeHeaders = await client.signRequest('GET', '/api/status');
  (fakeHeaders as Record<string, string>)['X-BPC-Pair-ID'] = 'pair_nonexistent999';

  const fakeRes = await fetch(`${SERVER}/api/status`, {
    method: 'GET',
    headers: fakeHeaders as unknown as Record<string, string>,
  });
  const fakeBody = await fakeRes.json() as Record<string, unknown>;
  const fakeBlocked = fakeRes.status === 401 && fakeBody.error === 'unknown_pair';
  label('Unknown pair ID', fakeBlocked, `status=${fakeRes.status} error=${fakeBody.error}`);

  // --- Step 8: Revocation ---
  console.log('\n7. Testing revocation...');
  const revokeRes = await fetch(`${SERVER}/bpc/revoke`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${process.env['BPC_ADMIN_TOKEN'] ?? 'change-me-in-production-use-32-random-bytes'}`,
    },
    body: JSON.stringify({ pairId: regBody.pairId }),
  });
  const revokeBody = await revokeRes.json() as Record<string, unknown>;
  label('Revocation accepted', revokeRes.status === 200 && revokeBody.revoked === true, `status=${revokeRes.status}`);

  // Revoked pair should be rejected
  const revokedHeaders = await client.signRequest('GET', '/api/status');
  const revokedRes = await fetch(`${SERVER}/api/status`, { method: 'GET', headers: revokedHeaders as unknown as Record<string, string> });
  const revokedBody = await revokedRes.json() as Record<string, unknown>;
  label('Revoked pair rejected', revokedRes.status === 401 && revokedBody.error === 'pair_revoked', `status=${revokedRes.status} error=${revokedBody.error}`);

  // Re-register for remaining tests
  const { keypair: keypair2, request: request2 } = await prepareRegistration(DEVICE_NAME + '-2', SECRET, 'read-write', 'development');
  const regRes2 = await fetch(`${SERVER}/bpc/register`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(request2) });
  const regBody2 = await regRes2.json() as { pairId: string };
  const client2 = new BPCClient({ serverUrl: SERVER, pairId: regBody2.pairId, keypair: keypair2, secret: SECRET });

  // --- Step 9: Key rotation ---
  console.log('\n8. Testing key rotation...');
  const newKeypair = await generateKeypair();
  const rotResult = await client2.rotate(newKeypair.pubJwk);
  const rotOk = typeof rotResult.newPairId === 'string' && rotResult.newPairId.startsWith('pair_');
  label('Rotation succeeded', rotOk, `newPairId=${rotResult.newPairId}`);

  // Old pair should now be rejected (rotated status)
  const oldHeaders = await client2.signRequest('GET', '/api/status');
  const oldRes = await fetch(`${SERVER}/api/status`, { method: 'GET', headers: oldHeaders as unknown as Record<string, string> });
  const oldBody = await oldRes.json() as Record<string, unknown>;
  label('Old pair rejected after rotation', oldRes.status === 401 && oldBody.error === 'pair_rotated', `status=${oldRes.status} error=${oldBody.error}`);

  // New pair should work
  const newClient = new BPCClient({ serverUrl: SERVER, pairId: rotResult.newPairId, keypair: newKeypair, secret: SECRET });
  const newRes = await newClient.fetch('/api/status');
  label('New pair accepted after rotation', newRes.status === 200, `status=${newRes.status}`);

  // --- Summary ---
  console.log('\n=== End-to-End Test Complete ===');
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
