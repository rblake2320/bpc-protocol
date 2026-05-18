/**
 * BPC Audit Log
 *
 * IL4-7 hardening:
 *  - AuditEntry extended with `userAgent`, `severity`, and `requestId` fields
 *    to satisfy NIST SP 800-53 AU-2 (Event Logging) and AU-3 (Content of Records).
 *  - MemoryAuditLog ring buffer increased to 10,000 entries.
 *  - Added `queryAll()` for global audit trail access (admin use only).
 *  - PgAuditLog schema updated with user_agent, severity, request_id columns.
 *
 * NIST SP 800-53 Rev 5 controls: AU-2, AU-3, AU-9, AU-12.
 */

export type AuditAction = 'verify_pass' | 'verify_fail' | 'register' | 'revoke' | 'rotate' | 'lockout';
export type AuditSeverity = 'info' | 'warn' | 'critical';

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
}

export interface AuditLog {
  write(entry: Omit<AuditEntry, 'id' | 'timestamp'>): Promise<void>;
  query(pairId: string, limit?: number): Promise<AuditEntry[]>;
  queryAll?(limit?: number): Promise<AuditEntry[]>;
}

let _auditIdCounter = 0;
function auditId(): string {
  return `audit_${Date.now()}_${(++_auditIdCounter).toString(36)}`;
}

/** In-memory ring-buffer audit log (last 10,000 entries for IL4-7 compliance). */
export class MemoryAuditLog implements AuditLog {
  private entries: AuditEntry[] = [];
  private readonly maxSize: number;

  constructor(maxSize = 10_000) {
    this.maxSize = maxSize;
  }

  async write(entry: Omit<AuditEntry, 'id' | 'timestamp'>): Promise<void> {
    const full: AuditEntry = {
      ...entry,
      id:        auditId(),
      timestamp: Date.now(),
      severity:  entry.severity ?? (entry.error ? 'warn' : 'info'),
    };
    this.entries.push(full);
    if (this.entries.length > this.maxSize) {
      this.entries.shift();
    }
  }

  async query(pairId: string, limit = 100): Promise<AuditEntry[]> {
    return this.entries
      .filter(e => e.pairId === pairId)
      .slice(-limit)
      .reverse();
  }

  async queryAll(limit = 1000): Promise<AuditEntry[]> {
    return [...this.entries].reverse().slice(0, limit);
  }

  /** @deprecated Use queryAll() instead. */
  all(): AuditEntry[] { return [...this.entries].reverse(); }
}

/**
 * PostgreSQL-backed audit log.
 *
 * Schema:
 *   CREATE TABLE IF NOT EXISTS bpc_audit (
 *     id TEXT PRIMARY KEY,
 *     timestamp BIGINT NOT NULL,
 *     action TEXT NOT NULL,
 *     pair_id TEXT,
 *     error TEXT,
 *     ip TEXT,
 *     method TEXT,
 *     path TEXT
 *   );
 *   CREATE INDEX IF NOT EXISTS bpc_audit_pair_idx ON bpc_audit(pair_id);
 *   CREATE INDEX IF NOT EXISTS bpc_audit_ts_idx ON bpc_audit(timestamp);
 */
export interface PgAuditPool {
  query(sql: string, params?: unknown[]): Promise<{ rows: Record<string, unknown>[] }>;
}

export class PgAuditLog implements AuditLog {
  constructor(private pool: PgAuditPool) {}

  async write(entry: Omit<AuditEntry, 'id' | 'timestamp'>): Promise<void> {
    const full: AuditEntry = {
      ...entry,
      id:        auditId(),
      timestamp: Date.now(),
      severity:  entry.severity ?? (entry.error ? 'warn' : 'info'),
    };
    await this.pool.query(
      `INSERT INTO bpc_audit
         (id, timestamp, action, severity, pair_id, error, ip, method, path, user_agent, request_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
      [
        full.id, full.timestamp, full.action, full.severity,
        full.pairId ?? null, full.error ?? null, full.ip ?? null,
        full.method ?? null, full.path ?? null,
        full.userAgent ?? null, full.requestId ?? null,
      ],
    );
  }

  async query(pairId: string, limit = 100): Promise<AuditEntry[]> {
    const { rows } = await this.pool.query(
      'SELECT * FROM bpc_audit WHERE pair_id = $1 ORDER BY timestamp DESC LIMIT $2',
      [pairId, limit],
    );
    return rows.map(r => ({
      id:        r['id'] as string,
      timestamp: Number(r['timestamp']),
      action:    r['action'] as AuditAction,
      severity:  (r['severity'] as AuditSeverity) ?? 'info',
      pairId:    r['pair_id'] as string | undefined,
      error:     r['error'] as string | undefined,
      ip:        r['ip'] as string | undefined,
      method:    r['method'] as string | undefined,
      path:      r['path'] as string | undefined,
      userAgent: r['user_agent'] as string | undefined,
      requestId: r['request_id'] as string | undefined,
    }));
  }

  async queryAll(limit = 1000): Promise<AuditEntry[]> {
    const { rows } = await this.pool.query(
      'SELECT * FROM bpc_audit ORDER BY timestamp DESC LIMIT $1',
      [limit],
    );
    return rows.map(r => ({
      id:        r['id'] as string,
      timestamp: Number(r['timestamp']),
      action:    r['action'] as AuditAction,
      severity:  (r['severity'] as AuditSeverity) ?? 'info',
      pairId:    r['pair_id'] as string | undefined,
      error:     r['error'] as string | undefined,
      ip:        r['ip'] as string | undefined,
      method:    r['method'] as string | undefined,
      path:      r['path'] as string | undefined,
      userAgent: r['user_agent'] as string | undefined,
      requestId: r['request_id'] as string | undefined,
    }));
  }
}

export const PG_AUDIT_SCHEMA = `
CREATE TABLE IF NOT EXISTS bpc_audit (
  id          TEXT PRIMARY KEY,
  timestamp   BIGINT NOT NULL,
  action      TEXT NOT NULL,
  severity    TEXT NOT NULL DEFAULT 'info',
  pair_id     TEXT,
  error       TEXT,
  ip          TEXT,
  method      TEXT,
  path        TEXT,
  user_agent  TEXT,
  request_id  TEXT
);
CREATE INDEX IF NOT EXISTS bpc_audit_pair_idx ON bpc_audit(pair_id);
CREATE INDEX IF NOT EXISTS bpc_audit_ts_idx   ON bpc_audit(timestamp);
CREATE INDEX IF NOT EXISTS bpc_audit_sev_idx  ON bpc_audit(severity);
`;
