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

/**
 * Synchronous, side-effect-free pair transformation executed under the store's
 * authority lock/transaction. Implementations must pass a detached snapshot to
 * the callback and persist only the returned value.
 */
export type PairAtomicMutation = (
  current: Readonly<StoredPair>,
) => StoredPair | undefined;

/**
 * Pair authority operations that cannot be safely composed from get/set calls.
 * Production registries should require this capability. Legacy PairStore
 * implementations remain supported only for bounded, single-writer use.
 */
export interface AtomicPairStore extends PairStore {
  atomicMutate(pairId: string, mutate: PairAtomicMutation): Promise<StoredPair | undefined>;
  approvePending(
    token: string,
    expected: { registration: PairRegistration; requestedAt: number },
    pair: StoredPair,
    maxActivePairs: number,
  ): Promise<boolean>;
  rotatePair(expectedOld: StoredPair, replacement: StoredPair): Promise<boolean>;
  claimSuccessfulUse(pairId: string, at: number): Promise<boolean>;
}

export function isAtomicPairStore(store: PairStore): store is AtomicPairStore {
  const value = store as Partial<AtomicPairStore>;
  return typeof value.atomicMutate === 'function'
    && typeof value.approvePending === 'function'
    && typeof value.rotatePair === 'function'
    && typeof value.claimSuccessfulUse === 'function';
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
