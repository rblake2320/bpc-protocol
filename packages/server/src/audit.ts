export type AuditAction = 'verify_pass' | 'verify_fail' | 'register' | 'revoke' | 'rotate' | 'lockout';

export interface AuditEntry {
  id: string;
  timestamp: number;
  action: AuditAction;
  pairId?: string;
  error?: string;
  ip?: string;
  method?: string;
  path?: string;
}

export interface AuditLog {
  write(entry: Omit<AuditEntry, 'id' | 'timestamp'>): Promise<void>;
  query(pairId: string, limit?: number): Promise<AuditEntry[]>;
}

let _auditIdCounter = 0;
function auditId(): string {
  return `audit_${Date.now()}_${(++_auditIdCounter).toString(36)}`;
}

/** In-memory ring-buffer audit log (last 1000 entries). */
export class MemoryAuditLog implements AuditLog {
  private entries: AuditEntry[] = [];
  private readonly maxSize: number;

  constructor(maxSize = 1000) {
    this.maxSize = maxSize;
  }

  async write(entry: Omit<AuditEntry, 'id' | 'timestamp'>): Promise<void> {
    const full: AuditEntry = { id: auditId(), timestamp: Date.now(), ...entry };
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
    const full: AuditEntry = { id: auditId(), timestamp: Date.now(), ...entry };
    await this.pool.query(
      `INSERT INTO bpc_audit (id, timestamp, action, pair_id, error, ip, method, path)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [full.id, full.timestamp, full.action, full.pairId ?? null,
       full.error ?? null, full.ip ?? null, full.method ?? null, full.path ?? null]
    );
  }

  async query(pairId: string, limit = 100): Promise<AuditEntry[]> {
    const { rows } = await this.pool.query(
      'SELECT * FROM bpc_audit WHERE pair_id = $1 ORDER BY timestamp DESC LIMIT $2',
      [pairId, limit]
    );
    return rows.map(r => ({
      id: r['id'] as string,
      timestamp: Number(r['timestamp']),
      action: r['action'] as AuditAction,
      pairId: r['pair_id'] as string | undefined,
      error: r['error'] as string | undefined,
      ip: r['ip'] as string | undefined,
      method: r['method'] as string | undefined,
      path: r['path'] as string | undefined,
    }));
  }
}

export const PG_AUDIT_SCHEMA = `
CREATE TABLE IF NOT EXISTS bpc_audit (
  id TEXT PRIMARY KEY,
  timestamp BIGINT NOT NULL,
  action TEXT NOT NULL,
  pair_id TEXT,
  error TEXT,
  ip TEXT,
  method TEXT,
  path TEXT
);
CREATE INDEX IF NOT EXISTS bpc_audit_pair_idx ON bpc_audit(pair_id);
CREATE INDEX IF NOT EXISTS bpc_audit_ts_idx ON bpc_audit(timestamp);
`;
