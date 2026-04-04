import type { PairStore, NonceStoreBackend, AnomalyStore } from './store.js';
import type { StoredPair, PairRegistration } from './types.js';

export class MemoryPairStore implements PairStore {
  private pairs = new Map<string, StoredPair>();
  private pending = new Map<string, { registration: PairRegistration; requestedAt: number }>();

  async get(pairId: string) { return this.pairs.get(pairId); }
  async set(pair: StoredPair) { this.pairs.set(pair.id, pair); }
  async delete(pairId: string) { this.pairs.delete(pairId); }
  async list() { return Array.from(this.pairs.values()); }
  async getPending(token: string) { return this.pending.get(token); }
  async setPending(token: string, registration: PairRegistration, requestedAt: number) {
    this.pending.set(token, { registration, requestedAt });
  }
  async deletePending(token: string) { this.pending.delete(token); }
  async listPending() {
    return Array.from(this.pending.entries()).map(([token, v]) => ({ token, ...v }));
  }
}

/** Hard cap on in-memory nonce storage. At ~580 RPS with 120s TTL, steady state is ~70k entries.
 *  100k gives ~40% headroom. Exceeded cap → evict oldest 10% to shed load gracefully.
 *  For sustained >800 RPS use RedisNonceStore instead. */
const MAX_NONCE_ENTRIES = 100_000;

export class MemoryNonceBackend implements NonceStoreBackend {
  private seen = new Map<string, number>(); // nonce → expiresAt

  async checkAndConsume(nonce: string, ttlMs: number): Promise<boolean> {
    const now = Date.now();
    // Evict expired nonces
    for (const [k, exp] of this.seen) {
      if (exp < now) this.seen.delete(k);
    }
    if (this.seen.has(nonce)) return true; // replay
    // Capacity guard: evict oldest 10% if at cap
    if (this.seen.size >= MAX_NONCE_ENTRIES) {
      const evictCount = Math.ceil(MAX_NONCE_ENTRIES * 0.1);
      let evicted = 0;
      for (const k of this.seen.keys()) {
        if (evicted >= evictCount) break;
        this.seen.delete(k);
        evicted++;
      }
    }
    this.seen.set(nonce, now + ttlMs);
    return false;
  }
}

export class MemoryAnomalyStore implements AnomalyStore {
  private counters = new Map<string, { value: number; expiresAt: number }>();

  async increment(key: string, ttlMs = 3_600_000): Promise<number> {
    const now = Date.now();
    const entry = this.counters.get(key);
    if (!entry || entry.expiresAt < now) {
      this.counters.set(key, { value: 1, expiresAt: now + ttlMs });
      return 1;
    }
    entry.value++;
    return entry.value;
  }

  async get(key: string): Promise<number> {
    const now = Date.now();
    const entry = this.counters.get(key);
    if (!entry || entry.expiresAt < now) return 0;
    return entry.value;
  }

  async reset(key: string): Promise<void> {
    this.counters.delete(key);
  }
}
