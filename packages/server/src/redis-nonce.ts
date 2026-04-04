/**
 * Redis-backed nonce store for distributed/multi-process deployments.
 * Requires peerDependency: ioredis
 *
 * Uses Redis SET with NX + PX flags for atomic check-and-set.
 * TTL = 2 x sigWindowMs + 10s buffer (default: 130s)
 */

import type { NonceStoreBackend } from './store.js';

export interface RedisClient {
  set(key: string, value: string, nx: 'NX', px: 'PX', ttlMs: number): Promise<'OK' | null>;
}

export class RedisNonceStore implements NonceStoreBackend {
  private prefix: string;

  constructor(private redis: RedisClient, prefix = 'bpc:nonce:') {
    this.prefix = prefix;
  }

  async checkAndConsume(nonce: string, ttlMs: number): Promise<boolean> {
    // SET key value NX PX ttlMs — only sets if key does not exist
    // Returns 'OK' if key was set (nonce is fresh), null if key already existed (replay)
    const result = await this.redis.set(this.prefix + nonce, '1', 'NX', 'PX', ttlMs);
    return result === null; // null = key existed = replay detected
  }
}
