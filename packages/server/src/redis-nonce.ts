/**
 * Redis-backed nonce store for distributed/multi-process deployments.
 * Requires peerDependency: ioredis
 *
 * Uses Redis SET with NX + PX flags for atomic check-and-set.
 * TTL = 2 x sigWindowMs + 10s buffer (default: 130s)
 */

import type { NonceStoreBackend } from './store.js';
import { NonceStoreUnavailableError, ServerNonceStore } from './nonce-store.js';

export interface RedisClient {
  set(key: string, value: string, nx: 'NX', px: 'PX', ttlMs: number): Promise<'OK' | null>;
}

export interface RedisBackedNonceOptions {
  /** Isolates nonce keys by deployment/environment. */
  namespace: string;
  /** Must match the verifier's BPC signature acceptance window. */
  sigWindowMs: number;
  /** Additional retention beyond twice the signature window. Default: 10s. */
  safetyBufferMs?: number;
  /** Maximum time to wait for one Redis SET before failing closed. Default: 2s. */
  commandTimeoutMs?: number;
  /**
   * Required acknowledgement that this low-level helper has no continuity
   * epoch/quarantine. Production Redis verifiers must use the async governed
   * factory instead.
   */
  continuityMode: 'ungoverned-development';
}

export interface RedisBackedNonceStore {
  nonceStore: ServerNonceStore;
  retentionMs: number;
  keyPrefix: string;
}

export const DEFAULT_NONCE_SAFETY_BUFFER_MS = 10_000;
export const DEFAULT_REDIS_NONCE_TIMEOUT_MS = 2_000;

const NAMESPACE_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

function positiveSafeInteger(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new RangeError(`${label} must be a positive safe integer`);
  }
  return value;
}

export function deriveNonceRetentionMs(
  sigWindowMs: number,
  safetyBufferMs = DEFAULT_NONCE_SAFETY_BUFFER_MS,
): number {
  positiveSafeInteger(sigWindowMs, 'sigWindowMs');
  if (!Number.isSafeInteger(safetyBufferMs) || safetyBufferMs < 0) {
    throw new RangeError('safetyBufferMs must be a non-negative safe integer');
  }
  const retentionMs = sigWindowMs * 2 + safetyBufferMs;
  if (!Number.isSafeInteger(retentionMs)) {
    throw new RangeError('Derived nonce retention exceeds the safe integer range');
  }
  return retentionMs;
}

async function withTimeout<T>(operation: Promise<T>, timeoutMs: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () => reject(new NonceStoreUnavailableError(new Error('Redis nonce command timed out'))),
      timeoutMs,
    );
  });
  try {
    return await Promise.race([operation, timeout]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

export class RedisNonceStore implements NonceStoreBackend {
  private prefix: string;

  constructor(
    private redis: RedisClient,
    prefix = 'bpc:nonce:',
    private commandTimeoutMs = DEFAULT_REDIS_NONCE_TIMEOUT_MS,
  ) {
    positiveSafeInteger(commandTimeoutMs, 'commandTimeoutMs');
    if (prefix.length === 0) throw new RangeError('Redis nonce key prefix must not be empty');
    this.prefix = prefix;
  }

  async checkAndConsume(nonce: string, ttlMs: number): Promise<boolean> {
    // SET key value NX PX ttlMs — only sets if key does not exist
    // Returns 'OK' if key was set (nonce is fresh), null if key already existed (replay)
    positiveSafeInteger(ttlMs, 'ttlMs');
    try {
      const result = await withTimeout(
        this.redis.set(this.prefix + nonce, '1', 'NX', 'PX', ttlMs),
        this.commandTimeoutMs,
      );
      if (result !== 'OK' && result !== null) {
        throw new Error('Redis returned an invalid SET response');
      }
      return result === null; // null = key existed = replay detected
    } catch (error) {
      if (error instanceof NonceStoreUnavailableError) throw error;
      throw new NonceStoreUnavailableError(error);
    }
  }
}

/**
 * Explicitly ungoverned low-level composition for tests and development.
 * It binds TTL and namespace but cannot detect Redis state loss or failover.
 * Production Redis verifiers must use createGovernedRedisBackedNonceStore().
 */
export function createRedisBackedNonceStore(
  redis: RedisClient,
  options: RedisBackedNonceOptions,
): RedisBackedNonceStore {
  if (options.continuityMode !== 'ungoverned-development') {
    throw new RangeError('continuityMode must explicitly be ungoverned-development');
  }
  if (!NAMESPACE_RE.test(options.namespace)) {
    throw new RangeError('namespace must be 1-64 ASCII letters, digits, dot, underscore, or hyphen');
  }
  const retentionMs = deriveNonceRetentionMs(options.sigWindowMs, options.safetyBufferMs);
  const commandTimeoutMs = options.commandTimeoutMs ?? DEFAULT_REDIS_NONCE_TIMEOUT_MS;
  positiveSafeInteger(commandTimeoutMs, 'commandTimeoutMs');
  const keyPrefix = `bpc:${options.namespace}:nonce:`;
  return {
    nonceStore: new ServerNonceStore(
      new RedisNonceStore(redis, keyPrefix, commandTimeoutMs),
      retentionMs,
    ),
    retentionMs,
    keyPrefix,
  };
}
