import assert from 'node:assert/strict';
import pg from 'pg';
import { PG_SCHEMA, PgPairStore } from './packages/server/src/index.ts';
import type { PairRegistration, StoredPair } from './packages/server/src/index.ts';

const connectionString = process.env['BPC_TEST_POSTGRES_URL'];
if (!connectionString) {
  throw new Error('BPC_TEST_POSTGRES_URL is required for the live PostgreSQL test');
}

const { Pool } = pg;
const legacySchema = `
CREATE TABLE IF NOT EXISTS bpc_pairs (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  scope TEXT NOT NULL,
  mode TEXT NOT NULL,
  secret_hash TEXT NOT NULL,
  pub_jwk JSONB NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  created BIGINT NOT NULL,
  last_active BIGINT,
  requests INT NOT NULL DEFAULT 0,
  failed_sigs INT NOT NULL DEFAULT 0,
  expires_at BIGINT
);
CREATE TABLE IF NOT EXISTS bpc_pending (
  token TEXT PRIMARY KEY,
  registration JSONB NOT NULL,
  requested_at BIGINT NOT NULL
);`;
const suffix = `${process.pid}_${Date.now()}`;
const pairId = `pair_pg_${suffix}`;
const pendingToken = `pending_pg_${suffix}`;
const publicKey: JsonWebKey = {
  kty: 'EC',
  crv: 'P-256',
  x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  y: 'B'.repeat(42) + 'E',
};

const pair: StoredPair = {
  id: pairId,
  name: 'postgres-live-ghost',
  scope: 'read-write',
  mode: 'production',
  secretHash: 'C'.repeat(42)+'Q',
  pubJwk: publicKey,
  status: 'active',
  created: Date.now(),
  lastActive: Date.now() - 1_000,
  requests: 9,
  failedSigs: 4,
  cumulativeFailures: 7.5,
  firstFailureAt: Date.now() - 5_000,
  maxRequests: 10,
  kind: 'ghost',
  canaryClass: 'registry_exfil',
  expiresAt: Date.now() + 60_000,
};

const pending: PairRegistration = {
  name: 'postgres-pending',
  scope: 'read',
  mode: 'production',
  secretHash: 'D'.repeat(42)+'Q',
  pubJwk: publicKey,
  maxRequests: 3,
};

let pool = new Pool({ connectionString, max: 2 });
try {
  await pool.query('DROP TABLE IF EXISTS bpc_pending, bpc_pairs CASCADE');
  // The deprecated standalone DDL is explicitly fresh-only: it must not
  // pretend CREATE IF NOT EXISTS upgraded a weaker legacy catalog.
  await pool.query(legacySchema);
  await assert.rejects(() => pool.query(PG_SCHEMA), /fresh-only/);
  await pool.query('DROP TABLE bpc_pending, bpc_pairs');
  await pool.query(PG_SCHEMA);
  let store = new PgPairStore(pool);

  await store.set(pair);
  assert.deepEqual(await store.get(pairId), pair);

  await store.setPending(pendingToken, pending, 100);
  await store.setPending(pendingToken, { ...pending, name: 'postgres-pending-updated' }, 200);
  assert.deepEqual(await store.getPending(pendingToken), {
    registration: { ...pending, name: 'postgres-pending-updated' },
    requestedAt: 200,
  });

  // Reconnect before reading to distinguish database persistence from process state.
  await pool.end();
  pool = new Pool({ connectionString, max: 2 });
  store = new PgPairStore(pool);

  assert.deepEqual(await store.get(pairId), pair);
  assert.equal((await store.list()).some(candidate => candidate.id === pairId), true);
  assert.equal((await store.listPending()).some(candidate => candidate.token === pendingToken), true);

  await store.set({ ...pair, status: 'revoked', requests: 10 });
  const revoked = await store.get(pairId);
  assert.equal(revoked?.status, 'revoked');
  assert.equal(revoked?.requests, 10);
  assert.equal(revoked?.maxRequests, 10);
  assert.equal(revoked?.kind, 'ghost');
  assert.equal(revoked?.canaryClass, 'registry_exfil');
  assert.equal(revoked?.cumulativeFailures, 7.5);

  await store.deletePending(pendingToken);
  await store.delete(pairId);
  assert.equal(await store.getPending(pendingToken), undefined);
  assert.equal(await store.get(pairId), undefined);

  console.log(
    'PostgreSQL store integration: PASS ' +
      '(legacy refusal, strict fresh schema, security fields, pending lifecycle, reconnect durability)',
  );
} finally {
  try {
    await pool.query('DELETE FROM bpc_pending WHERE token = $1', [pendingToken]);
    await pool.query('DELETE FROM bpc_pairs WHERE id = $1', [pairId]);
  } finally {
    await pool.end().catch(() => undefined);
  }
}
