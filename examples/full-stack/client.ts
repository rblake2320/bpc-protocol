import { BPCClient, prepareRegistration } from '../../packages/client-sdk/src/index.ts';
import { generateNonce, generateId } from '../../packages/core/src/index.ts';

const SERVER = 'http://localhost:3100';
const SECRET = 'demo-secret-' + Date.now();
const DEVICE_NAME = 'e2e-test-client';

function label(name: string, ok: boolean, detail?: string): void {
  const tag = ok ? 'PASS' : 'FAIL';
  const extra = detail ? ` — ${detail}` : '';
  console.log(`  [${tag}] ${name}${extra}`);
}

async function main(): Promise<void> {
  console.log('=== BPC Full-Stack End-to-End Test ===\n');

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
  let savedHeaders: Record<string, string> | null = null;

  for (let i = 1; i <= 3; i++) {
    const res = await client.fetch('/api/status');
    const body = await res.json() as Record<string, unknown>;
    const ok = res.status === 200 && body.status === 'ok';
    label(`GET /api/status (${i}/3)`, ok, `status=${res.status}`);

    // Save headers from request #2 for the replay test later
    if (i === 2) {
      savedHeaders = await client.signRequest('GET', '/api/status') as unknown as Record<string, string>;
      // Actually, we need the headers that were SENT. Let's re-sign to get usable headers.
      // The nonce from this signRequest call is fresh but unused — perfect for replay test.
    }
  }

  // --- Step 4: One signed request to /api/users ---
  console.log('\n3. Sending signed request to /api/users...');
  const usersRes = await client.fetch('/api/users');
  const usersBody = await usersRes.json() as Record<string, unknown>;
  const usersOk = usersRes.status === 200 && Array.isArray(usersBody.users);
  label('GET /api/users', usersOk, `users=${JSON.stringify(usersBody.users)}`);

  // --- Step 5: Replay attack ---
  console.log('\n4. Attempting replay attack (reusing old headers)...');

  // First, make a legitimate request and capture the headers
  const replayHeaders = await client.signRequest('GET', '/api/status');

  // Use these headers once (legitimate)
  const legitRes = await fetch(`${SERVER}/api/status`, {
    method: 'GET',
    headers: replayHeaders as unknown as Record<string, string>,
  });
  const legitOk = legitRes.status === 200;
  label('Legitimate request (sets nonce)', legitOk, `status=${legitRes.status}`);

  // Now replay the exact same headers — should be rejected
  const replayRes = await fetch(`${SERVER}/api/status`, {
    method: 'GET',
    headers: replayHeaders as unknown as Record<string, string>,
  });
  const replayBody = await replayRes.json() as Record<string, unknown>;
  const replayBlocked = replayRes.status === 401 && replayBody.error === 'replay_detected';
  label('Replay attempt', replayBlocked, `status=${replayRes.status} error=${replayBody.error}`);

  // --- Step 6: Unknown pair ID ---
  console.log('\n5. Attempting request with unknown pair ID...');

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

  // --- Summary ---
  console.log('\n=== End-to-End Test Complete ===');
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
