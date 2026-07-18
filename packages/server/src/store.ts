import type { StoredPair, PairRegistration } from './types.js';
import { types as utilTypes } from 'node:util';

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

export type SuccessfulUseClaim = 'claimed' | 'missing' | 'inactive' | 'policy-changed' | 'time-expired' | 'usage-exhausted';

/** Authorization-relevant state that must still match at final use claim. */
export interface SuccessfulUsePolicy {
  readonly status: StoredPair['status'];
  readonly scope: StoredPair['scope'];
  readonly mode: StoredPair['mode'];
  readonly secretHash: string;
  readonly pubJwk: JsonWebKey;
  readonly expiresAt?: number;
  readonly maxRequests?: number;
  readonly kind: NonNullable<StoredPair['kind']>;
  readonly canaryClass?: StoredPair['canaryClass'];
}

export interface CanonicalAuthorizationJwk {
  readonly kty: 'EC';
  readonly crv: 'P-256';
  readonly x: string;
  readonly y: string;
}

const JWK_FIELDS = new Set(['kty', 'crv', 'x', 'y', 'key_ops', 'ext']);
const B64URL_256 = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;

/** Canonical public-key identity used by verification and final policy claims. */
export function canonicalAuthorizationJwk(value: unknown): CanonicalAuthorizationJwk {
  if (!value || typeof value !== 'object' || utilTypes.isProxy(value)) throw new Error('pubJwk must be a non-proxy object');
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) throw new Error('pubJwk must be a plain object');
  if (Object.getOwnPropertySymbols(value).length) throw new Error('pubJwk cannot contain symbols');
  const fields = value as Record<string, unknown>;
  for (const key of Object.getOwnPropertyNames(fields)) {
    if (!JWK_FIELDS.has(key)) throw new Error(`pubJwk contains unexpected field '${key}'`);
    const descriptor = Object.getOwnPropertyDescriptor(fields, key)!;
    if (!('value' in descriptor) || !descriptor.enumerable) throw new Error(`pubJwk.${key} must be an enumerable data property`);
  }
  const own = (key: string) => Object.getOwnPropertyDescriptor(fields, key)?.value;
  const kty = own('kty'), crv = own('crv'), x = own('x'), y = own('y');
  if (kty !== 'EC' || crv !== 'P-256' || typeof x !== 'string' || !B64URL_256.test(x) || typeof y !== 'string' || !B64URL_256.test(y)) {
    throw new Error('pubJwk must be an exact public P-256 key');
  }
  const keyOps = own('key_ops');
  if (keyOps !== undefined) {
    if (!Array.isArray(keyOps) || utilTypes.isProxy(keyOps) || keyOps.length !== 1 || Object.getOwnPropertySymbols(keyOps).length || Object.getOwnPropertyNames(keyOps).some((key) => key !== '0' && key !== 'length')) {
      throw new Error('pubJwk.key_ops must be exactly ["verify"] when present');
    }
    const item = Object.getOwnPropertyDescriptor(keyOps, '0');
    if (!item || !('value' in item) || !item.enumerable || item.value !== 'verify') throw new Error('pubJwk.key_ops must contain one verify data property');
  }
  const ext = own('ext');
  if (ext !== undefined && ext !== true) throw new Error('pubJwk.ext must be true when present');
  return Object.freeze({ kty: 'EC', crv: 'P-256', x, y });
}

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
  return pair.name===registration.name&&pair.scope===registration.scope&&pair.mode===registration.mode&&pair.secretHash===registration.secretHash&&sameData(canonicalAuthorizationJwk(pair.pubJwk),canonicalAuthorizationJwk(registration.pubJwk))&&pair.expiresAt===registration.expiresAt&&pair.maxRequests===registration.maxRequests&&(pair.kind??'legitimate')===(registration.kind??'legitimate')&&pair.canaryClass===registration.canaryClass;
}

export function rotationPolicyMatches(oldPair: Readonly<StoredPair>, replacement: Readonly<StoredPair>): boolean {
  return oldPair.name===replacement.name&&oldPair.scope===replacement.scope&&oldPair.mode===replacement.mode&&oldPair.secretHash===replacement.secretHash&&oldPair.expiresAt===replacement.expiresAt&&oldPair.maxRequests===replacement.maxRequests&&(oldPair.kind??'legitimate')===(replacement.kind??'legitimate')&&oldPair.canaryClass===replacement.canaryClass;
}

export function successfulUsePolicy(pair: Readonly<StoredPair>): SuccessfulUsePolicy {
  return {
    status: pair.status,
    scope: pair.scope,
    mode: pair.mode,
    secretHash: pair.secretHash,
    pubJwk: canonicalAuthorizationJwk(pair.pubJwk),
    expiresAt: pair.expiresAt,
    maxRequests: pair.maxRequests,
    kind: pair.kind ?? 'legitimate',
    canaryClass: pair.canaryClass,
  };
}

export function successfulUsePolicyMatches(pair: Readonly<StoredPair>, expected: Readonly<SuccessfulUsePolicy>): boolean {
  return pair.status === expected.status
    && pair.scope === expected.scope
    && pair.mode === expected.mode
    && pair.secretHash === expected.secretHash
    && sameData(canonicalAuthorizationJwk(pair.pubJwk), canonicalAuthorizationJwk(expected.pubJwk))
    && pair.expiresAt === expected.expiresAt
    && pair.maxRequests === expected.maxRequests
    && (pair.kind ?? 'legitimate') === expected.kind
    && pair.canaryClass === expected.canaryClass;
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
  claimSuccessfulUse(pairId: string, at: number, expected: SuccessfulUsePolicy): Promise<SuccessfulUseClaim>;
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
