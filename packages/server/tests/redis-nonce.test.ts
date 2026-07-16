import { describe, expect, it } from 'vitest';

import {
  NonceStoreUnavailableError,
  ServerNonceStore,
} from '../src/nonce-store.js';
import {
  RedisNonceStore,
  createRedisBackedNonceStore,
  deriveNonceRetentionMs,
  type RedisClient,
} from '../src/redis-nonce.js';
import { createBPCServer } from '../src/index.js';

class RecordingRedis implements RedisClient {
  readonly calls: Array<{ key: string; ttlMs: number }> = [];
  private keys = new Set<string>();

  async set(key: string, _value: string, _nx: 'NX', _px: 'PX', ttlMs: number): Promise<'OK' | null> {
    this.calls.push({ key, ttlMs });
    if (this.keys.has(key)) return null;
    this.keys.add(key);
    return 'OK';
  }
}

describe('standalone Redis nonce composition', () => {
  it('derives retention from both sides of the signature window plus safety buffer', () => {
    expect(deriveNonceRetentionMs(60_000)).toBe(130_000);
    expect(deriveNonceRetentionMs(1_000, 500)).toBe(2_500);
  });

  it.each([
    [0, 10_000],
    [-1, 10_000],
    [Number.NaN, 10_000],
    [60_000, -1],
    [60_000, Number.POSITIVE_INFINITY],
  ])('rejects unsafe retention inputs (%s, %s)', (windowMs, bufferMs) => {
    expect(() => deriveNonceRetentionMs(windowMs, bufferMs)).toThrow(RangeError);
  });

  it.each(['', 'contains space', ':shared', 'a'.repeat(65), 'prod:tenant'])
  ('requires a bounded explicit namespace: %s', (namespace) => {
    expect(() => createRedisBackedNonceStore(new RecordingRedis(), {
      namespace,
      sigWindowMs: 60_000,
      continuityMode: 'ungoverned-development',
    })).toThrow(RangeError);
  });

  it('binds the namespace and derived retention to each Redis write', async () => {
    const redis = new RecordingRedis();
    const configured = createRedisBackedNonceStore(redis, {
      namespace: 'prod-us1',
      sigWindowMs: 60_000,
      continuityMode: 'ungoverned-development',
    });

    expect(configured.keyPrefix).toBe('bpc:prod-us1:nonce:');
    expect(configured.retentionMs).toBe(130_000);
    await expect(configured.nonceStore.checkAndConsume('nonce-a')).resolves.toBe(false);
    await expect(configured.nonceStore.checkAndConsume('nonce-a')).resolves.toBe(true);
    expect(redis.calls).toEqual([
      { key: 'bpc:prod-us1:nonce:nonce-a', ttlMs: 130_000 },
      { key: 'bpc:prod-us1:nonce:nonce-a', ttlMs: 130_000 },
    ]);
  });

  it('injects the configured Redis nonce store into a standalone server instance', () => {
    const configured = createRedisBackedNonceStore(new RecordingRedis(), {
      namespace: 'standalone',
      sigWindowMs: 60_000,
      continuityMode: 'ungoverned-development',
    });
    const server = createBPCServer({ nonceStore: configured.nonceStore });
    expect(server.nonceStore).toBe(configured.nonceStore);
  });

  it('fails closed with a named error when Redis rejects the write', async () => {
    const redis: RedisClient = {
      set: async () => { throw new Error('OOM command not allowed'); },
    };
    const { nonceStore } = createRedisBackedNonceStore(redis, {
      namespace: 'oom-test',
      sigWindowMs: 60_000,
      continuityMode: 'ungoverned-development',
    });
    await expect(nonceStore.checkAndConsume('nonce-b')).rejects.toBeInstanceOf(NonceStoreUnavailableError);
  });

  it('fails closed when Redis does not answer within the command deadline', async () => {
    const redis: RedisClient = {
      set: () => new Promise<'OK' | null>(() => {}),
    };
    const { nonceStore } = createRedisBackedNonceStore(redis, {
      namespace: 'timeout-test',
      sigWindowMs: 60_000,
      continuityMode: 'ungoverned-development',
      commandTimeoutMs: 10,
    });
    await expect(nonceStore.checkAndConsume('nonce-c')).rejects.toBeInstanceOf(NonceStoreUnavailableError);
  });

  it('fails closed on an invalid Redis protocol response', async () => {
    const redis = {
      set: async () => 'QUEUED',
    } as unknown as RedisClient;
    const store = new ServerNonceStore(new RedisNonceStore(redis, 'bpc:test:nonce:'), 130_000);
    await expect(store.checkAndConsume('nonce-d')).rejects.toBeInstanceOf(NonceStoreUnavailableError);
  });

  it('rejects invalid retention and timeout configuration before serving requests', () => {
    expect(() => new ServerNonceStore(new RedisNonceStore(new RecordingRedis()), 0)).toThrow(RangeError);
    expect(() => new RedisNonceStore(new RecordingRedis(), 'bpc:test:', 0)).toThrow(RangeError);
  });

  it('requires an explicit acknowledgement that the low-level helper is ungoverned', () => {
    expect(() => createRedisBackedNonceStore(new RecordingRedis(), {
      namespace: 'missing-ack',
      sigWindowMs: 60_000,
    } as never)).toThrow('continuityMode must explicitly be ungoverned-development');
  });
});
