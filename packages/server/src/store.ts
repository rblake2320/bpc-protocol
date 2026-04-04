import type { StoredPair, PairRegistration } from './types.js';

/** Abstract interface for pair persistence. */
export interface PairStore {
  get(pairId: string): Promise<StoredPair | undefined>;
  set(pair: StoredPair): Promise<void>;
  delete(pairId: string): Promise<void>;
  list(): Promise<StoredPair[]>;
  getPending(token: string): Promise<{ registration: PairRegistration; requestedAt: number } | undefined>;
  setPending(token: string, registration: PairRegistration, requestedAt: number): Promise<void>;
  deletePending(token: string): Promise<void>;
  listPending(): Promise<Array<{ token: string; registration: PairRegistration; requestedAt: number }>>;
}

/** Abstract interface for nonce storage. */
export interface NonceStoreBackend {
  /** Returns true if nonce was already seen (replay). Adds it if not. */
  checkAndConsume(nonce: string, ttlMs: number): Promise<boolean>;
}

/** Abstract interface for anomaly counter storage. */
export interface AnomalyStore {
  increment(key: string, ttlMs?: number): Promise<number>;
  get(key: string): Promise<number>;
  reset(key: string): Promise<void>;
}
