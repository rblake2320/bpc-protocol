export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: number;  // Unix ms when window resets
}

export interface RateLimiter {
  check(key: string): Promise<RateLimitResult>;
}

/** In-memory sliding window rate limiter. */
export class MemoryRateLimiter implements RateLimiter {
  // key → array of request timestamps
  private windows = new Map<string, number[]>();

  constructor(
    private readonly limit: number,
    private readonly windowMs: number,
  ) {}

  async check(key: string): Promise<RateLimitResult> {
    const now = Date.now();
    const cutoff = now - this.windowMs;

    let timestamps = this.windows.get(key) ?? [];
    // Evict expired timestamps
    timestamps = timestamps.filter(t => t > cutoff);

    const allowed = timestamps.length < this.limit;
    if (allowed) timestamps.push(now);

    this.windows.set(key, timestamps);

    return {
      allowed,
      remaining: Math.max(0, this.limit - timestamps.length),
      resetAt: (timestamps[0] ?? now) + this.windowMs,
    };
  }
}

/** Redis sliding window rate limiter using a sorted set. */
export interface RedisZSetClient {
  zadd(key: string, score: number, member: string): Promise<number>;
  zremrangebyscore(key: string, min: number | string, max: number): Promise<number>;
  zcard(key: string): Promise<number>;
  expire(key: string, seconds: number): Promise<number>;
}

export class RedisRateLimiter implements RateLimiter {
  constructor(
    private redis: RedisZSetClient,
    private readonly limit: number,
    private readonly windowMs: number,
    private readonly prefix = 'bpc:ratelimit:',
  ) {}

  async check(key: string): Promise<RateLimitResult> {
    const now = Date.now();
    const cutoff = now - this.windowMs;
    const fullKey = this.prefix + key;

    // Remove expired entries
    await this.redis.zremrangebyscore(fullKey, '-inf', cutoff);
    const count = await this.redis.zcard(fullKey);

    if (count >= this.limit) {
      return { allowed: false, remaining: 0, resetAt: now + this.windowMs };
    }

    // Add current request
    await this.redis.zadd(fullKey, now, `${now}-${Math.random()}`);
    await this.redis.expire(fullKey, Math.ceil(this.windowMs / 1000) + 1);

    return {
      allowed: true,
      remaining: this.limit - count - 1,
      resetAt: now + this.windowMs,
    };
  }
}
