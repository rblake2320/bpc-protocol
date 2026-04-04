/**
 * Redis-backed anomaly counter store.
 * Requires peerDependency: ioredis
 */

import type { AnomalyStore } from './store.js';

export interface RedisIncrClient {
  incr(key: string): Promise<number>;
  get(key: string): Promise<string | null>;
  del(key: string): Promise<number>;
  expire(key: string, seconds: number): Promise<number>;
  ttl(key: string): Promise<number>;
}

export class RedisAnomalyStore implements AnomalyStore {
  constructor(private redis: RedisIncrClient, private prefix = 'bpc:anomaly:') {}

  async increment(key: string, ttlMs = 3_600_000): Promise<number> {
    const fullKey = this.prefix + key;
    const val = await this.redis.incr(fullKey);
    // Only set TTL on first increment (val === 1) to preserve sliding window
    if (val === 1) {
      await this.redis.expire(fullKey, Math.ceil(ttlMs / 1000));
    }
    return val;
  }

  async get(key: string): Promise<number> {
    const val = await this.redis.get(this.prefix + key);
    return val ? parseInt(val, 10) : 0;
  }

  async reset(key: string): Promise<void> {
    await this.redis.del(this.prefix + key);
  }
}
