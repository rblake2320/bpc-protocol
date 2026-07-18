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

export type SuccessfulUseClaim = 'claimed' | 'missing' | 'inactive' | 'time-expired' | 'usage-exhausted';

function sameData(left: unknown, right: unknown): boolean {
  if (Object.is(left, right)) return true;
  if (!left || !right || typeof left !== 'object' || typeof right !== 'object') return false;
  if (Object.getOwnPropertySymbols(left).length || Object.getOwnPropertySymbols(right).length) return false;
  const leftKeys=Object.keys(left).sort(),rightKeys=Object.keys(right).sort();
  if (leftKeys.length!==rightKeys.length||leftKeys.some((key,index)=>key!==rightKeys[index])) return false;
  return leftKeys.every((key)=>{const a=Object.getOwnPropertyDescriptor(left,key),b=Object.getOwnPropertyDescriptor(right,key);return !!a&&!!b&&'value'in a&&'value'in b&&a.enumerable&&b.enumerable&&sameData(a.value,b.value);});
}

export function hasInitialPairState(pair: Readonly<StoredPair>): boolean {
  return pair.status==='active'&&pair.lastActive===null&&pair.requests===0&&pair.failedSigs===0&&pair.cumulativeFailures===undefined&&pair.firstFailureAt===undefined;
}

export function pairMatchesRegistration(pair: Readonly<StoredPair>, registration: Readonly<PairRegistration>): boolean {
  return pair.name===registration.name&&pair.scope===registration.scope&&pair.mode===registration.mode&&pair.secretHash===registration.secretHash&&sameData(pair.pubJwk,registration.pubJwk)&&pair.expiresAt===registration.expiresAt&&pair.maxRequests===registration.maxRequests&&(pair.kind??'legitimate')===(registration.kind??'legitimate')&&pair.canaryClass===registration.canaryClass;
}

export function rotationPolicyMatches(oldPair: Readonly<StoredPair>, replacement: Readonly<StoredPair>): boolean {
  return oldPair.name===replacement.name&&oldPair.scope===replacement.scope&&oldPair.mode===replacement.mode&&oldPair.secretHash===replacement.secretHash&&oldPair.expiresAt===replacement.expiresAt&&oldPair.maxRequests===replacement.maxRequests&&(oldPair.kind??'legitimate')===(replacement.kind??'legitimate')&&oldPair.canaryClass===replacement.canaryClass;
}

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
  claimSuccessfulUse(pairId: string, at: number): Promise<SuccessfulUseClaim>;
  expireIfElapsed(pairId: string, now: number): Promise<boolean>;
  expireIfUsageExhausted(pairId: string): Promise<boolean>;
  lockIfFailureThreshold(pairId: string, minimumFailures: number): Promise<boolean>;
}

export function isAtomicPairStore(store: PairStore): store is AtomicPairStore {
  const value = store as Partial<AtomicPairStore>;
  return typeof value.atomicMutate === 'function'
    && typeof value.approvePending === 'function'
    && typeof value.rotatePair === 'function'
    && typeof value.claimSuccessfulUse === 'function'
    && typeof value.expireIfElapsed === 'function'
    && typeof value.expireIfUsageExhausted === 'function'
    && typeof value.lockIfFailureThreshold === 'function';
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
