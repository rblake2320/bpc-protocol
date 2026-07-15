/**
 * BPC Audit Log — hash-chained, tamper-evident.
 *
 * Candidate NIST SP 800-53 Rev 5 evidence: AU-2, AU-3, AU-9, AU-10, AU-12.
 *
 * Tamper-evidence model:
 *  - Every entry carries a monotonic `seq`, the previous entry's `chainHash`
 *    (`prevHash`), and its own `chainHash = SHA-256(canonical(entry))`.
 *  - Any in-place modification of a historical entry changes its chainHash and
 *    breaks the link of every subsequent entry — detected by verifyChain().
 *  - Tail TRUNCATION / rollback is detected via an external anchor: callers
 *    persist head() = { seq, chainHash } and pass it to verifyChain({ expectedHead }).
 *    A shorter/forked chain than the anchor fails verification.
 *  - MemoryAuditLog is append-only by default (no silent eviction) so the
 *    in-memory trail does not silently evict entries; durable storage uses PgAuditLog.
 *  - PgAuditLog stores the chain columns and the schema REVOKEs UPDATE/DELETE/
 *    TRUNCATE and installs triggers that hard-block mutation (defense in depth).
 */

import { createHash } from 'node:crypto';

export type AuditAction =
  | 'verify_pass'
  | 'verify_fail'
  | 'register'
  | 'revoke'
  | 'rotate'
  | 'lockout'
  // Layer 8 Active Defense actions
  | 'shadow_mode_hit'
  | 'shadow_mode_enter'
  | 'ghost_pair_triggered';

export type AuditSeverity = 'info' | 'warn' | 'critical' | 'HIGH' | 'CRITICAL';

export interface AuditEntry {
  id: string;
  timestamp: number;
  action: AuditAction;
  severity?: AuditSeverity;
  pairId?: string;
  error?: string;
  ip?: string;
  method?: string;
  path?: string;
  userAgent?: string;
  requestId?: string;
  /** Layer 8: Additional forensic detail (JSON string for ghost/shadow events). */
  detail?: string;
  // ── Hash-chain fields (assigned by write()) ──────────────────────────────
  /** Monotonic 1-based sequence number. */
  seq: number;
  /** chainHash of the immediately preceding entry (GENESIS for the first). */
  prevHash: string;
  /** SHA-256 over the canonical encoding of this entry, including seq + prevHash. */
  chainHash: string;
}

/** Fields the caller supplies to write(); chain + id + timestamp are derived. */
export type AuditInput = Omit<AuditEntry, 'id' | 'timestamp' | 'seq' | 'prevHash' | 'chainHash'>;

export interface ChainHead {
  seq: number;
  chainHash: string;
  /** Total entries written over the lifetime of the log (>= retained count). */
  count: number;
}

export interface VerifyResult {
  valid: boolean;
  /** seq at which verification failed, if any. */
  brokenAtSeq?: number;
  reason?: string;
}

export interface AuditLog {
  write(entry: AuditInput): Promise<void>;
  query(pairId: string, limit?: number): Promise<AuditEntry[]>;
  queryAll?(limit?: number): Promise<AuditEntry[]>;
  /** Verify chain integrity; pass a persisted anchor to also detect truncation. */
  verifyChain?(opts?: { expectedHead?: ChainHead }): Promise<VerifyResult>;
  /** Current chain head — persist this externally as the truncation anchor. */
  head?(): Promise<ChainHead>;
}

/** Genesis predecessor hash for the first entry in any chain. */
export const GENESIS_HASH = '0'.repeat(64);

let _auditIdCounter = 0;
function auditId(): string {
  return `audit_${Date.now()}_${(++_auditIdCounter).toString(36)}`;
}

function sha256hex(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

/**
 * Deterministic canonical preimage for an entry's chainHash.
 * Fixed field order; JSON-array encoding so free-text fields (error/detail/path)
 * cannot inject delimiter collisions. Optional fields normalize to null.
 * Identical function is used by Memory and Pg implementations → guaranteed parity.
 */
function chainPreimage(e: {
  seq: number; prevHash: string; id: string; timestamp: number;
  action: AuditAction; severity: AuditSeverity;
  pairId?: string; error?: string; ip?: string; method?: string;
  path?: string; userAgent?: string; requestId?: string; detail?: string;
}): string {
  return JSON.stringify([
    e.seq, e.prevHash, e.id, e.timestamp, e.action, e.severity,
    e.pairId ?? null, e.error ?? null, e.ip ?? null, e.method ?? null,
    e.path ?? null, e.userAgent ?? null, e.requestId ?? null, e.detail ?? null,
  ]);
}

function computeChainHash(e: Omit<AuditEntry, 'chainHash'>): string {
  return sha256hex(chainPreimage({ ...e, severity: e.severity ?? 'info' }));
}

/** Shared chain verifier used by every AuditLog implementation. */
export function verifyEntries(
  entries: AuditEntry[],
  opts: { expectedHead?: ChainHead } = {},
): VerifyResult {
  const sorted = [...entries].sort((a, b) => a.seq - b.seq);

  for (let i = 0; i < sorted.length; i++) {
    const e = sorted[i];
    const recomputed = computeChainHash(e);
    if (recomputed !== e.chainHash) {
      return { valid: false, brokenAtSeq: e.seq, reason: 'entry_hash_mismatch' };
    }
    if (i > 0) {
      const prev = sorted[i - 1];
      if (e.seq !== prev.seq + 1) {
        return { valid: false, brokenAtSeq: e.seq, reason: 'non_contiguous_seq' };
      }
      if (e.prevHash !== prev.chainHash) {
        return { valid: false, brokenAtSeq: e.seq, reason: 'broken_link' };
      }
    }
  }

  const anchor = opts.expectedHead;
  if (anchor) {
    const last = sorted[sorted.length - 1];
    if (!last || last.seq < anchor.seq) {
      return { valid: false, brokenAtSeq: anchor.seq, reason: 'truncated_below_anchor' };
    }
    const atAnchor = sorted.find(e => e.seq === anchor.seq);
    if (!atAnchor || atAnchor.chainHash !== anchor.chainHash) {
      return { valid: false, brokenAtSeq: anchor.seq, reason: 'anchor_mismatch' };
    }
  }

  return { valid: true };
}

/**
 * In-memory append-only audit log.
 * Append-only by default (maxSize = Infinity), but still process-local and
 * unsigned. A finite maxSize enables bounded memory but is then a lossy
 * archival mode — pair it with PgAuditLog for durable, complete history.
 */
export class MemoryAuditLog implements AuditLog {
  private entries: AuditEntry[] = [];
  private readonly maxSize: number;
  private seqCounter = 0;
  private headHash = GENESIS_HASH;
  private totalWritten = 0;

  constructor(maxSize = Number.POSITIVE_INFINITY) {
    this.maxSize = maxSize;
  }

  async write(entry: AuditInput): Promise<void> {
    const seq = ++this.seqCounter;
    const base: Omit<AuditEntry, 'chainHash'> = {
      ...entry,
      id:        auditId(),
      timestamp: Date.now(),
      severity:  entry.severity ?? (entry.error ? 'warn' : 'info'),
      seq,
      prevHash:  this.headHash,
    };
    const full: AuditEntry = { ...base, chainHash: computeChainHash(base) };
    this.entries.push(full);
    this.headHash = full.chainHash;
    this.totalWritten++;
    if (this.entries.length > this.maxSize) {
      this.entries.shift(); // bounded mode only; retained window stays contiguous
    }
  }

  async query(pairId: string, limit = 100): Promise<AuditEntry[]> {
    return this.entries.filter(e => e.pairId === pairId).slice(-limit).reverse();
  }

  async queryAll(limit = 1000): Promise<AuditEntry[]> {
    return [...this.entries].reverse().slice(0, limit);
  }

  async head(): Promise<ChainHead> {
    return { seq: this.seqCounter, chainHash: this.headHash, count: this.totalWritten };
  }

  async verifyChain(opts: { expectedHead?: ChainHead } = {}): Promise<VerifyResult> {
    return verifyEntries(this.entries, opts);
  }

  /** Test/inspection helper: raw retained entries (do not mutate in production). */
  snapshot(): AuditEntry[] { return [...this.entries]; }
}

export interface PgAuditPool {
  query(sql: string, params?: unknown[]): Promise<{ rows: Record<string, unknown>[] }>;
}

function isUniqueViolation(err: unknown): boolean {
  return !!err && typeof err === 'object' && (err as { code?: string }).code === '23505';
}

/**
 * PostgreSQL-backed, hash-chained audit log.
 * chainHash is computed app-side with the SAME function as MemoryAuditLog
 * (guaranteed parity). Concurrency safety: UNIQUE(seq) rejects racing appends;
 * the loser retries against the new head. Storage-layer tamper protection is
 * provided by PG_AUDIT_SCHEMA (REVOKE + no-mutation triggers).
 */
export class PgAuditLog implements AuditLog {
  constructor(private pool: PgAuditPool, private maxRetries = 5) {}

  async write(entry: AuditInput): Promise<void> {
    const id        = auditId();
    const timestamp = Date.now();
    const severity  = entry.severity ?? (entry.error ? 'warn' : 'info');

    for (let attempt = 0; attempt < this.maxRetries; attempt++) {
      const { rows } = await this.pool.query(
        'SELECT seq, chain_hash FROM bpc_audit ORDER BY seq DESC LIMIT 1',
      );
      const prevSeq  = rows[0] ? Number(rows[0]['seq']) : 0;
      const prevHash = rows[0] ? String(rows[0]['chain_hash']) : GENESIS_HASH;
      const seq      = prevSeq + 1;

      const base: Omit<AuditEntry, 'chainHash'> = {
        ...entry, id, timestamp, severity, seq, prevHash,
      };
      const chainHash = computeChainHash(base);

      try {
        await this.pool.query(
          `INSERT INTO bpc_audit
             (id, seq, timestamp, action, severity, pair_id, error, ip, method, path,
              user_agent, request_id, detail, prev_hash, chain_hash)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
          [
            id, seq, timestamp, entry.action, severity,
            entry.pairId ?? null, entry.error ?? null, entry.ip ?? null,
            entry.method ?? null, entry.path ?? null, entry.userAgent ?? null,
            entry.requestId ?? null, entry.detail ?? null, prevHash, chainHash,
          ],
        );
        return;
      } catch (err) {
        if (isUniqueViolation(err)) continue; // racing append — retry on new head
        throw err;
      }
    }
    throw new Error('bpc_audit: append contention exceeded retry budget');
  }

  private mapRow(r: Record<string, unknown>): AuditEntry {
    return {
      id:        r['id'] as string,
      timestamp: Number(r['timestamp']),
      action:    r['action'] as AuditAction,
      severity:  (r['severity'] as AuditSeverity) ?? 'info',
      pairId:    (r['pair_id'] as string | null) ?? undefined,
      error:     (r['error'] as string | null) ?? undefined,
      ip:        (r['ip'] as string | null) ?? undefined,
      method:    (r['method'] as string | null) ?? undefined,
      path:      (r['path'] as string | null) ?? undefined,
      userAgent: (r['user_agent'] as string | null) ?? undefined,
      requestId: (r['request_id'] as string | null) ?? undefined,
      detail:    (r['detail'] as string | null) ?? undefined,
      seq:       Number(r['seq']),
      prevHash:  r['prev_hash'] as string,
      chainHash: r['chain_hash'] as string,
    };
  }

  async query(pairId: string, limit = 100): Promise<AuditEntry[]> {
    const { rows } = await this.pool.query(
      'SELECT * FROM bpc_audit WHERE pair_id = $1 ORDER BY seq DESC LIMIT $2',
      [pairId, limit],
    );
    return rows.map(r => this.mapRow(r));
  }

  async queryAll(limit = 1000): Promise<AuditEntry[]> {
    const { rows } = await this.pool.query(
      'SELECT * FROM bpc_audit ORDER BY seq DESC LIMIT $1',
      [limit],
    );
    return rows.map(r => this.mapRow(r));
  }

  async head(): Promise<ChainHead> {
    const { rows } = await this.pool.query(
      'SELECT seq, chain_hash FROM bpc_audit ORDER BY seq DESC LIMIT 1',
    );
    const { rows: c } = await this.pool.query('SELECT COUNT(*)::int AS n FROM bpc_audit');
    const count = c[0] ? Number(c[0]['n']) : 0;
    if (!rows[0]) return { seq: 0, chainHash: GENESIS_HASH, count };
    return { seq: Number(rows[0]['seq']), chainHash: String(rows[0]['chain_hash']), count };
  }

  async verifyChain(opts: { expectedHead?: ChainHead } = {}): Promise<VerifyResult> {
    const { rows } = await this.pool.query('SELECT * FROM bpc_audit ORDER BY seq ASC');
    return verifyEntries(rows.map(r => this.mapRow(r)), opts);
  }
}

/**
 * Hardened, append-only Postgres schema.
 * - Chain columns (seq UNIQUE, prev_hash, chain_hash).
 * - REVOKE UPDATE/DELETE/TRUNCATE from PUBLIC (also revoke from your app role).
 * - Row-level triggers block UPDATE and DELETE; statement-level trigger blocks
 *   TRUNCATE (row triggers do NOT fire on TRUNCATE — this closes that gap).
 */
export const PG_AUDIT_SCHEMA = `
CREATE TABLE IF NOT EXISTS bpc_audit (
  id          TEXT PRIMARY KEY,
  seq         BIGINT NOT NULL,
  timestamp   BIGINT NOT NULL,
  action      TEXT NOT NULL,
  severity    TEXT NOT NULL DEFAULT 'info',
  pair_id     TEXT,
  error       TEXT,
  ip          TEXT,
  method      TEXT,
  path        TEXT,
  user_agent  TEXT,
  request_id  TEXT,
  detail      TEXT,
  prev_hash   TEXT NOT NULL,
  chain_hash  TEXT NOT NULL,
  CONSTRAINT bpc_audit_seq_unique UNIQUE (seq)
);
CREATE INDEX IF NOT EXISTS bpc_audit_pair_idx ON bpc_audit(pair_id);
CREATE INDEX IF NOT EXISTS bpc_audit_ts_idx   ON bpc_audit(timestamp);
CREATE INDEX IF NOT EXISTS bpc_audit_sev_idx  ON bpc_audit(severity);

CREATE OR REPLACE FUNCTION bpc_audit_block_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'bpc_audit is append-only: % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS bpc_audit_no_update ON bpc_audit;
CREATE TRIGGER bpc_audit_no_update BEFORE UPDATE ON bpc_audit
  FOR EACH ROW EXECUTE FUNCTION bpc_audit_block_mutation();

DROP TRIGGER IF EXISTS bpc_audit_no_delete ON bpc_audit;
CREATE TRIGGER bpc_audit_no_delete BEFORE DELETE ON bpc_audit
  FOR EACH ROW EXECUTE FUNCTION bpc_audit_block_mutation();

DROP TRIGGER IF EXISTS bpc_audit_no_truncate ON bpc_audit;
CREATE TRIGGER bpc_audit_no_truncate BEFORE TRUNCATE ON bpc_audit
  FOR EACH STATEMENT EXECUTE FUNCTION bpc_audit_block_mutation();

REVOKE UPDATE, DELETE, TRUNCATE ON bpc_audit FROM PUBLIC;
-- Also: REVOKE UPDATE, DELETE, TRUNCATE ON bpc_audit FROM <your_app_role>;
`;
