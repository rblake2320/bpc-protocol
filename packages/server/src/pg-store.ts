/**
 * PostgreSQL-backed pair store for production deployments.
 *
 * Requires peerDependency: pg
 * Schema (run before use):
 *
 *   CREATE TABLE IF NOT EXISTS bpc_pairs (
 *     id TEXT PRIMARY KEY,
 *     name TEXT NOT NULL,
 *     scope TEXT NOT NULL,
 *     mode TEXT NOT NULL,
 *     secret_hash TEXT NOT NULL,
 *     pub_jwk JSONB NOT NULL,
 *     status TEXT NOT NULL DEFAULT 'active',
 *     created BIGINT NOT NULL,
 *     last_active BIGINT,
 *     requests INT NOT NULL DEFAULT 0,
 *     failed_sigs INT NOT NULL DEFAULT 0,
 *     expires_at BIGINT
 *   );
 *
 *   CREATE TABLE IF NOT EXISTS bpc_pending (
 *     token TEXT PRIMARY KEY,
 *     registration JSONB NOT NULL,
 *     requested_at BIGINT NOT NULL
 *   );
 */

import type { PairStore } from './store.js';
import type { StoredPair, PairRegistration } from './types.js';

export interface PgPool {
  query(sql: string, params?: unknown[]): Promise<{ rows: Record<string, unknown>[] }>;
}

function rowToStoredPair(row: Record<string, unknown>): StoredPair {
  return {
    id: row['id'] as string,
    name: row['name'] as string,
    scope: row['scope'] as StoredPair['scope'],
    mode: row['mode'] as StoredPair['mode'],
    secretHash: row['secret_hash'] as string,
    pubJwk: row['pub_jwk'] as JsonWebKey,
    status: row['status'] as StoredPair['status'],
    created: Number(row['created']),
    lastActive: row['last_active'] != null ? Number(row['last_active']) : null,
    requests: Number(row['requests']),
    failedSigs: Number(row['failed_sigs']),
    expiresAt: row['expires_at'] != null ? Number(row['expires_at']) : undefined,
  };
}

export class PgPairStore implements PairStore {
  constructor(private pool: PgPool) {}

  async get(pairId: string): Promise<StoredPair | undefined> {
    const { rows } = await this.pool.query('SELECT * FROM bpc_pairs WHERE id = $1', [pairId]);
    return rows[0] ? rowToStoredPair(rows[0]) : undefined;
  }

  async set(pair: StoredPair): Promise<void> {
    await this.pool.query(
      `INSERT INTO bpc_pairs (id, name, scope, mode, secret_hash, pub_jwk, status, created, last_active, requests, failed_sigs, expires_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
       ON CONFLICT (id) DO UPDATE SET
         name=$2, scope=$3, mode=$4, secret_hash=$5, pub_jwk=$6, status=$7,
         last_active=$9, requests=$10, failed_sigs=$11, expires_at=$12`,
      [pair.id, pair.name, pair.scope, pair.mode, pair.secretHash,
       JSON.stringify(pair.pubJwk), pair.status, pair.created,
       pair.lastActive, pair.requests, pair.failedSigs, pair.expiresAt ?? null]
    );
  }

  async delete(pairId: string): Promise<void> {
    await this.pool.query('DELETE FROM bpc_pairs WHERE id = $1', [pairId]);
  }

  async list(): Promise<StoredPair[]> {
    const { rows } = await this.pool.query('SELECT * FROM bpc_pairs ORDER BY created DESC');
    return rows.map(rowToStoredPair);
  }

  async getPending(token: string) {
    const { rows } = await this.pool.query('SELECT * FROM bpc_pending WHERE token = $1', [token]);
    if (!rows[0]) return undefined;
    const row = rows[0];
    return { registration: row['registration'] as PairRegistration, requestedAt: Number(row['requested_at']) };
  }

  async setPending(token: string, registration: PairRegistration, requestedAt: number): Promise<void> {
    await this.pool.query(
      'INSERT INTO bpc_pending (token, registration, requested_at) VALUES ($1,$2,$3) ON CONFLICT (token) DO UPDATE SET registration=$2',
      [token, JSON.stringify(registration), requestedAt]
    );
  }

  async deletePending(token: string): Promise<void> {
    await this.pool.query('DELETE FROM bpc_pending WHERE token = $1', [token]);
  }

  async listPending() {
    const { rows } = await this.pool.query('SELECT * FROM bpc_pending ORDER BY requested_at ASC');
    return rows.map(row => ({
      token: row['token'] as string,
      registration: row['registration'] as PairRegistration,
      requestedAt: Number(row['requested_at']),
    }));
  }
}

export const PG_SCHEMA = `
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
);
`;
