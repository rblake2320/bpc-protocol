/**
 * FilePairStore — JSON-file-backed pair persistence for BPC.
 *
 * Survives server restarts. Suitable for single-node deployments,
 * local dev with persistence, and terminal identity management in PKA.
 *
 * For multi-node: use PgPairStore or RedisPairStore instead.
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import type { PairStore, NonceStoreBackend, AnomalyStore } from './store.js';
import type { StoredPair, PairRegistration } from './types.js';

// ── FilePairStore ─────────────────────────────────────────────────────────────

interface FileStoreData {
  pairs: Record<string, StoredPair>;
  pending: Record<string, { registration: PairRegistration; requestedAt: number }>;
}

export class FilePairStore implements PairStore {
  private data: FileStoreData = { pairs: {}, pending: {} };

  constructor(private readonly filePath: string) {
    this.load();
  }

  private load(): void {
    try {
      if (existsSync(this.filePath)) {
        const raw = readFileSync(this.filePath, 'utf8');
        this.data = JSON.parse(raw) as FileStoreData;
        this.data.pairs   ??= {};
        this.data.pending ??= {};
      }
    } catch {
      this.data = { pairs: {}, pending: {} };
    }
  }

  private flush(): void {
    const dir = dirname(this.filePath);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    writeFileSync(this.filePath, JSON.stringify(this.data, null, 2), 'utf8');
  }

  async get(pairId: string): Promise<StoredPair | undefined> {
    return this.data.pairs[pairId];
  }

  async set(pair: StoredPair): Promise<void> {
    this.data.pairs[pair.id] = pair;
    this.flush();
  }

  async delete(pairId: string): Promise<void> {
    delete this.data.pairs[pairId];
    this.flush();
  }

  async list(): Promise<StoredPair[]> {
    return Object.values(this.data.pairs);
  }

  async getPending(token: string) {
    return this.data.pending[token];
  }

  async setPending(token: string, registration: PairRegistration, requestedAt: number): Promise<void> {
    this.data.pending[token] = { registration, requestedAt };
    this.flush();
  }

  async deletePending(token: string): Promise<void> {
    delete this.data.pending[token];
    this.flush();
  }

  async listPending() {
    return Object.entries(this.data.pending).map(([token, v]) => ({ token, ...v }));
  }
}

// ── FileNonceBackend ──────────────────────────────────────────────────────────
// NOTE: Nonces are short-lived (60-130s TTL). We persist them to survive the
// window in which a captured request could be replayed after a server restart.
// Expired entries are pruned on each write to keep the file small.

interface NonceEntry { expiresAt: number; }

export class FileNonceBackend implements NonceStoreBackend {
  private seen: Record<string, NonceEntry> = {};

  constructor(private readonly filePath: string) {
    this.load();
  }

  private load(): void {
    try {
      if (existsSync(this.filePath)) {
        const raw = readFileSync(this.filePath, 'utf8');
        this.seen = JSON.parse(raw) as Record<string, NonceEntry>;
        // Immediately prune expired nonces from previous run
        const now = Date.now();
        for (const [k, v] of Object.entries(this.seen)) {
          if (v.expiresAt < now) delete this.seen[k];
        }
      }
    } catch {
      this.seen = {};
    }
  }

  private flush(): void {
    // Prune expired before writing
    const now = Date.now();
    for (const [k, v] of Object.entries(this.seen)) {
      if (v.expiresAt < now) delete this.seen[k];
    }
    const dir = dirname(this.filePath);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    writeFileSync(this.filePath, JSON.stringify(this.seen), 'utf8');
  }

  async checkAndConsume(nonce: string, ttlMs: number): Promise<boolean> {
    const now = Date.now();
    const entry = this.seen[nonce];
    if (entry && entry.expiresAt > now) return true; // replay
    this.seen[nonce] = { expiresAt: now + ttlMs };
    this.flush();
    return false;
  }
}

// ── FileAnomalyStore ──────────────────────────────────────────────────────────
// Counters with TTL persisted to disk. Useful for anomaly state that should
// survive a server restart during an active attack.

interface AnomalyEntry { value: number; expiresAt: number; }

export class FileAnomalyStore implements AnomalyStore {
  private counters: Record<string, AnomalyEntry> = {};

  constructor(private readonly filePath: string) {
    this.load();
  }

  private load(): void {
    try {
      if (existsSync(this.filePath)) {
        const raw = readFileSync(this.filePath, 'utf8');
        this.counters = JSON.parse(raw) as Record<string, AnomalyEntry>;
      }
    } catch {
      this.counters = {};
    }
  }

  private flush(): void {
    const now = Date.now();
    for (const [k, v] of Object.entries(this.counters)) {
      if (v.expiresAt < now) delete this.counters[k];
    }
    const dir = dirname(this.filePath);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    writeFileSync(this.filePath, JSON.stringify(this.counters), 'utf8');
  }

  async increment(key: string, ttlMs = 3_600_000): Promise<number> {
    const now = Date.now();
    const entry = this.counters[key];
    if (!entry || entry.expiresAt < now) {
      this.counters[key] = { value: 1, expiresAt: now + ttlMs };
    } else {
      entry.value++;
    }
    this.flush();
    return this.counters[key].value;
  }

  async get(key: string): Promise<number> {
    const now = Date.now();
    const entry = this.counters[key];
    if (!entry || entry.expiresAt < now) return 0;
    return entry.value;
  }

  async reset(key: string): Promise<void> {
    delete this.counters[key];
    this.flush();
  }
}
