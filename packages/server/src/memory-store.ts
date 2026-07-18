import { canonicalAuthorizationJwk, hasInitialPairState, pairMatchesRegistration, rotationPolicyMatches, successfulUsePolicyMatches, type AtomicPairStore, type PairAtomicMutation, type SuccessfulUseClaim, type SuccessfulUsePolicy, type NonceStoreBackend, type AnomalyStore } from './store.js';
import type { StoredPair, PairRegistration } from './types.js';

export class MemoryPairStore implements AtomicPairStore {
  private pairs = new Map<string, StoredPair>();
  private pending = new Map<string, { registration: PairRegistration; requestedAt: number }>();
  private authorityTail: Promise<void> = Promise.resolve();

  private async exclusively<T>(operation: () => T | Promise<T>): Promise<T> {
    const previous = this.authorityTail;
    let release!: () => void;
    this.authorityTail = new Promise<void>((resolve) => { release = resolve; });
    await previous;
    try { return await operation(); } finally { release(); }
  }

  async get(pairId: string) { const pair = this.pairs.get(pairId); return pair && structuredClone(pair); }
  async set(pair: StoredPair) { await this.exclusively(() => { this.pairs.set(pair.id, structuredClone(pair)); }); }
  async delete(pairId: string) { await this.exclusively(() => { this.pairs.delete(pairId); }); }
  async list() { return Array.from(this.pairs.values(), (value) => structuredClone(value)); }
  async getPending(token: string) { const value = this.pending.get(token); return value && structuredClone(value); }
  async setPending(token: string, registration: PairRegistration, requestedAt: number) {
    await this.exclusively(() => { this.pending.set(token, structuredClone({ registration, requestedAt })); });
  }
  async deletePending(token: string) { await this.exclusively(() => { this.pending.delete(token); }); }
  async listPending() {
    return Array.from(this.pending.entries()).map(([token, v]) => structuredClone({ token, ...v }));
  }

  async atomicMutate(pairId: string, mutate: PairAtomicMutation): Promise<StoredPair | undefined> {
    return this.exclusively(() => {
      const current = this.pairs.get(pairId);
      if (!current) return undefined;
      const next = mutate(Object.freeze(structuredClone(current)));
      if (!next) return structuredClone(current);
      if (next.id !== pairId) throw new Error('Atomic pair mutation cannot change pair identity');
      const saved = structuredClone(next);
      this.pairs.set(pairId, saved);
      return structuredClone(saved);
    });
  }

  async approvePending(
    token: string,
    expected: { registration: PairRegistration; requestedAt: number },
    pair: StoredPair,
    maxActivePairs: number,
  ): Promise<boolean> {
    return this.exclusively(() => {
      const pending = this.pending.get(token);
      if (!pending || JSON.stringify(pending) !== JSON.stringify(expected)) return false;
      if (!hasInitialPairState(pair) || !pairMatchesRegistration(pair, expected.registration)) {
        throw new Error('Approved pair initial state is invalid');
      }
      const active = Array.from(this.pairs.values()).filter((item) => item.status === 'active').length;
      if (active >= maxActivePairs) throw new Error(`Maximum pair capacity (${maxActivePairs}) reached`);
      if (this.pairs.has(pair.id)) throw new Error('Replacement pair identity already exists');
      this.pending.delete(token);
      this.pairs.set(pair.id, structuredClone(pair));
      return true;
    });
  }

  async rotatePair(expectedOld: StoredPair, replacement: StoredPair): Promise<boolean> {
    return this.exclusively(() => {
      const current = this.pairs.get(expectedOld.id);
      if (!current || JSON.stringify(current) !== JSON.stringify(expectedOld)) return false;
      if (current.status !== 'active' || !hasInitialPairState(replacement) || !rotationPolicyMatches(current,replacement) || this.pairs.has(replacement.id)) return false;
      this.pairs.set(current.id, { ...structuredClone(current), status: 'rotated' });
      this.pairs.set(replacement.id, structuredClone(replacement));
      return true;
    });
  }

  async claimSuccessfulUse(pairId: string, at: number, expected: SuccessfulUsePolicy): Promise<SuccessfulUseClaim> {
    if (!Number.isSafeInteger(at) || at < 0) throw new Error('Successful-use timestamp is invalid');
    const captured = { ...structuredClone(expected), pubJwk: canonicalAuthorizationJwk(expected.pubJwk) };
    return this.exclusively(() => {
      const current = this.pairs.get(pairId);
      if (!current) return 'missing';
      if (current.status === 'expired') {
        if (current.expiresAt !== undefined && current.expiresAt < at) return 'time-expired';
        if (current.maxRequests && current.maxRequests > 0 && current.requests >= current.maxRequests) return 'usage-exhausted';
      }
      if (current.status !== 'active') return 'inactive';
      if (current.expiresAt !== undefined && current.expiresAt < at) {
        this.pairs.set(pairId, { ...current, status: 'expired' });
        return 'time-expired';
      }
      if (current.maxRequests && current.maxRequests > 0 && current.requests >= current.maxRequests) {
        this.pairs.set(pairId, { ...current, status: 'expired' });
        return 'usage-exhausted';
      }
      if (!successfulUsePolicyMatches(current, captured)) return 'policy-changed';
      const requests = current.requests + 1;
      this.pairs.set(pairId, {
        ...current, requests, lastActive: at, failedSigs: 0,
        cumulativeFailures: 0, firstFailureAt: null,
        status: current.maxRequests && current.maxRequests > 0 && requests >= current.maxRequests ? 'expired' : current.status,
      });
      return 'claimed';
    });
  }

  async expireIfElapsed(pairId: string, now: number): Promise<boolean> {
    if (!Number.isSafeInteger(now) || now < 0) throw new Error('Expiry check timestamp is invalid');
    return this.exclusively(() => {
      const pair = this.pairs.get(pairId);
      if (!pair || pair.status !== 'active' || pair.expiresAt === undefined || pair.expiresAt >= now) return false;
      this.pairs.set(pairId, { ...pair, status: 'expired' });
      return true;
    });
  }

  async expireIfUsageExhausted(pairId: string): Promise<boolean> {
    return this.exclusively(() => {
      const pair = this.pairs.get(pairId);
      if (!pair || pair.status !== 'active' || !pair.maxRequests || pair.maxRequests <= 0 || pair.requests < pair.maxRequests) return false;
      this.pairs.set(pairId, { ...pair, status: 'expired' });
      return true;
    });
  }

  async lockIfFailureThreshold(pairId: string, minimumFailures: number): Promise<boolean> {
    if (!Number.isSafeInteger(minimumFailures) || minimumFailures < 1) throw new Error('Failure threshold is invalid');
    return this.exclusively(() => {
      const pair = this.pairs.get(pairId);
      if (!pair || pair.status !== 'active' || pair.failedSigs < minimumFailures) return false;
      this.pairs.set(pairId, { ...pair, status: 'locked' });
      return true;
    });
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
