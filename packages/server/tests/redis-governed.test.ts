import { describe, expect, it, vi } from 'vitest';

import { BPC_ERRORS } from '../src/errors.js';
import { NonceStoreUnavailableError } from '../src/nonce-store.js';
import {
  createGovernedRedisBackedNonceStore,
  RedisContinuityConfigurationError,
  type RedisAtomicClient,
} from '../src/redis-governed.js';
import {
  AuthorizationQuarantineError,
  EvictionPolicyError,
} from '../src/redis-continuity.js';

type StoredValue = { value: string; expiresAt?: number };

/**
 * Stateful model of the two governed Lua operations. Live Redis tests exercise
 * the actual scripts; this model makes every security transition observable.
 */
class FakeAtomicRedis implements RedisAtomicClient {
  readonly values = new Map<string, StoredValue>();
  policy: unknown = ['maxmemory-policy', 'noeviction'];
  configResult?: Promise<unknown>;
  beforeConsume?: () => void;
  failConsume?: unknown;
  invalidConsumeReply?: unknown;
  invalidReconcileReply?: unknown;

  async config(_op: 'GET', _parameter: string): Promise<unknown> {
    return this.configResult ?? this.policy;
  }

  private read(key: string): string | null {
    const item = this.values.get(key);
    if (item?.expiresAt !== undefined && item.expiresAt <= Date.now()) {
      this.values.delete(key);
      return null;
    }
    return item?.value ?? null;
  }

  private put(key: string, value: string, ttlMs?: number): void {
    this.values.set(key, {
      value,
      expiresAt: ttlMs === undefined ? undefined : Date.now() + ttlMs,
    });
  }

  private ttl(key: string): number {
    const value = this.values.get(key);
    if (!value || this.read(key) === null) return -2;
    if (value.expiresAt === undefined) return -1;
    return Math.max(0, value.expiresAt - Date.now());
  }

  setContinuity(namespace: string, epoch: string, config = '200:200'): void {
    this.put(`bpc:{${namespace}}:continuity:v2`, epoch);
    this.put(`bpc:{${namespace}}:continuity-config:v2`, config);
  }

  isQuarantined(namespace: string): boolean {
    return this.read(`bpc:{${namespace}}:continuity-quarantine:v2`) !== null;
  }

  quarantineTtl(namespace: string): number {
    return this.ttl(`bpc:{${namespace}}:continuity-quarantine:v2`);
  }

  hasNonce(namespace: string, nonce: string): boolean {
    return this.read(`bpc:{${namespace}}:nonce:${nonce}`) !== null;
  }

  async eval(
    _script: string | Buffer,
    numKeys: number | string,
    ...rawArgs: Array<string | Buffer | number>
  ): Promise<unknown> {
    const args = rawArgs.map(String);
    if (Number(numKeys) === 3) {
      if (this.invalidReconcileReply !== undefined) return this.invalidReconcileReply;
      const [continuityKey, quarantineKey, configKey, proposedEpoch, rawQuarantineMs,
        expectedEpoch, expectedConfig] = args;
      const quarantineMs = Number(rawQuarantineMs);
      let epoch = this.read(continuityKey);
      let config = this.read(configKey);
      let status = 'OK';
      const quarantineAtLeast = (value: string, minimum: number): number => {
        const duration = Math.max(minimum, this.ttl(quarantineKey));
        this.put(quarantineKey, value, duration);
        return this.ttl(quarantineKey);
      };
      if (config === null) {
        quarantineAtLeast(epoch ?? proposedEpoch, quarantineMs);
        this.put(configKey, expectedConfig);
        config = expectedConfig;
        status = 'CONFIG_ESTABLISHED';
      }
      const configMatch = /^(\d+):(\d+)$/.exec(config);
      const storedQuarantine = Number(configMatch?.[2]);
      if (!configMatch || Number(configMatch[1]) <= 0 || storedQuarantine <= 0) {
        return [
          'CONFIG_INVALID',
          epoch ?? proposedEpoch,
          String(quarantineAtLeast(epoch ?? proposedEpoch, quarantineMs)),
        ];
      }
      if (config !== expectedConfig) {
        return [
          'CONFIG_MISMATCH',
          epoch ?? proposedEpoch,
          String(quarantineAtLeast(epoch ?? proposedEpoch, Math.max(quarantineMs, storedQuarantine))),
        ];
      }
      if (epoch === null) {
        quarantineAtLeast(proposedEpoch, quarantineMs);
        this.put(continuityKey, proposedEpoch);
        epoch = proposedEpoch;
        status = 'MISSING';
      }
      if (expectedEpoch !== '' && epoch !== expectedEpoch) {
        quarantineAtLeast(epoch, quarantineMs);
        status = 'EPOCH_CHANGED';
      }
      const quarantine = this.read(quarantineKey);
      let ttl = this.ttl(quarantineKey);
      if (quarantine !== null && (quarantine !== epoch || ttl <= 0)) {
        ttl = quarantineAtLeast(epoch, quarantineMs);
      }
      return [status, epoch, String(ttl)];
    }

    if (Number(numKeys) !== 4) throw new Error('unexpected script');
    this.beforeConsume?.();
    if (this.failConsume !== undefined) throw this.failConsume;
    if (this.invalidConsumeReply !== undefined) return this.invalidConsumeReply;

    const [continuityKey, quarantineKey, configKey, nonceKey, expectedEpoch, replacementEpoch,
      rawQuarantineMs, rawTtlMs, expectedConfig] = args;
    const quarantineMs = Number(rawQuarantineMs);
    const ttlMs = Number(rawTtlMs);
    let epoch = this.read(continuityKey);
    let config = this.read(configKey);
    const quarantineAtLeast = (value: string, minimum: number): number => {
      const duration = Math.max(minimum, this.ttl(quarantineKey));
      this.put(quarantineKey, value, duration);
      return this.ttl(quarantineKey);
    };
    if (config === null) {
      const ttl = quarantineAtLeast(epoch ?? replacementEpoch, quarantineMs);
      this.put(configKey, expectedConfig);
      return ['CONFIG_MISSING', epoch ?? replacementEpoch, String(ttl)];
    }
    const configMatch = /^(\d+):(\d+)$/.exec(config);
    const storedQuarantine = Number(configMatch?.[2]);
    if (!configMatch || Number(configMatch[1]) <= 0 || storedQuarantine <= 0) {
      return [
        'CONFIG_INVALID',
        epoch ?? replacementEpoch,
        String(quarantineAtLeast(epoch ?? replacementEpoch, quarantineMs)),
      ];
    }
    if (config !== expectedConfig) {
      return [
        'CONFIG_MISMATCH',
        epoch ?? replacementEpoch,
        String(quarantineAtLeast(
          epoch ?? replacementEpoch,
          Math.max(quarantineMs, storedQuarantine),
        )),
      ];
    }
    if (epoch === null) {
      quarantineAtLeast(replacementEpoch, quarantineMs);
      this.put(continuityKey, replacementEpoch);
      epoch = replacementEpoch;
      return ['MISSING', epoch, String(this.ttl(quarantineKey))];
    }
    if (epoch !== expectedEpoch) {
      return ['EPOCH_CHANGED', epoch, String(quarantineAtLeast(epoch, quarantineMs))];
    }
    const quarantine = this.read(quarantineKey);
    if (quarantine !== null) {
      let ttl = this.ttl(quarantineKey);
      if (quarantine !== epoch || ttl <= 0) {
        ttl = quarantineAtLeast(epoch, quarantineMs);
        return ['MALFORMED', epoch, String(ttl)];
      }
      return ['QUARANTINED', epoch, String(ttl)];
    }
    if (this.read(nonceKey) !== null) return ['REPLAY', epoch, '-2'];
    this.put(nonceKey, '1', ttlMs);
    return ['FRESH', epoch, '-2'];
  }
}

class LateConsumeRedis extends FakeAtomicRedis {
  private intercepted = false;
  private markSettled!: () => void;
  readonly lateSettled = new Promise<void>((resolve) => { this.markSettled = resolve; });
  releaseLateCommand?: () => void;

  override async eval(
    script: string | Buffer,
    numKeys: number | string,
    ...args: Array<string | Buffer | number>
  ): Promise<unknown> {
    if (Number(numKeys) === 4 && !this.intercepted) {
      this.intercepted = true;
      return new Promise<unknown>((resolve) => {
        this.releaseLateCommand = () => {
          const nonceKey = String(args[3]);
          const expectedEpoch = String(args[4]);
          const ttlMs = Number(args[7]);
          this.values.set(nonceKey, { value: '1', expiresAt: Date.now() + ttlMs });
          resolve(['FRESH', expectedEpoch, '-2']);
          this.markSettled();
        };
      });
    }
    return super.eval(script, numKeys, ...args);
  }
}

function options(namespace: string, newEpoch = () => 'epoch-new') {
  return {
    namespace,
    sigWindowMs: 100,
    safetyBufferMs: 0,
    continuitySafetyAllowanceMs: 0,
    reconcileIntervalMs: 50,
    newEpoch,
  } as const;
}

describe('governed Redis replay composition', () => {
  it('fails startup closed before bootstrap when maxmemory-policy is not exact noeviction', async () => {
    const redis = new FakeAtomicRedis();
    redis.policy = ['wrong-key', 'noeviction'];
    await expect(createGovernedRedisBackedNonceStore(redis, options('unsafe')))
      .rejects.toBeInstanceOf(EvictionPolicyError);
  });

  it('does not return a usable store when startup policy inspection times out', async () => {
    const redis = new FakeAtomicRedis();
    redis.configResult = new Promise<unknown>(() => {});
    await expect(createGovernedRedisBackedNonceStore(redis, {
      ...options('config-timeout'),
      commandTimeoutMs: 10,
    })).rejects.toBeInstanceOf(NonceStoreUnavailableError);
  });

  it.each([
    [['MISSING', 'epoch-a', '-2']],
    [['EPOCH_CHANGED', 'epoch-a', '200']],
  ])('rejects an impossible bootstrap reply: %j', async (reply) => {
    const redis = new FakeAtomicRedis();
    redis.setContinuity('bad-bootstrap', 'epoch-a');
    redis.invalidReconcileReply = reply;
    await expect(createGovernedRedisBackedNonceStore(redis, {
      ...options('bad-bootstrap'),
      expectedEpoch: 'epoch-a',
    })).rejects.toBeInstanceOf(NonceStoreUnavailableError);
  });

  it('starts open only when an existing continuity epoch has no shared quarantine', async () => {
    const redis = new FakeAtomicRedis();
    redis.setContinuity('existing', 'epoch-established');
    const governed = await createGovernedRedisBackedNonceStore(redis, options('existing'));
    try {
      expect(governed.continuityEpoch).toBe('epoch-established');
      expect(governed.keyPrefix).toBe('bpc:{existing}:nonce:');
      expect(governed.continuityConfigKey).toBe('bpc:{existing}:continuity-config:v2');
      expect(Object.isFrozen(governed.verifierConfig)).toBe(true);
      expect(() => governed.continuityGuard.assertAcceptable()).not.toThrow();
      await expect(governed.nonceStore.checkAndConsume('n1')).resolves.toBe(false);
      await expect(governed.nonceStore.checkAndConsume('n1')).resolves.toBe(true);
    } finally {
      await governed.stop();
    }
  });

  it('puts two verifiers on a fresh namespace into the same shared quarantine', async () => {
    const redis = new FakeAtomicRedis();
    const first = await createGovernedRedisBackedNonceStore(redis, options('fresh', () => 'epoch-a'));
    const second = await createGovernedRedisBackedNonceStore(redis, options('fresh', () => 'epoch-b'));
    try {
      expect(first.continuityEpoch).toBe('epoch-a');
      expect(second.continuityEpoch).toBe('epoch-a');
      expect(redis.isQuarantined('fresh')).toBe(true);
      expect(() => first.continuityGuard.assertAcceptable()).toThrow(AuthorizationQuarantineError);
      expect(() => second.continuityGuard.assertAcceptable()).toThrow(AuthorizationQuarantineError);
      await expect(first.nonceStore.checkAndConsume('n1')).rejects.toBeInstanceOf(
        AuthorizationQuarantineError,
      );
      expect(redis.hasNonce('fresh', 'n1')).toBe(false);
    } finally {
      await Promise.all([first.stop(), second.stop()]);
    }
  });

  it('quarantines when a separately checkpointed expected epoch disagrees', async () => {
    const redis = new FakeAtomicRedis();
    redis.setContinuity('checkpoint', 'epoch-restored');
    const governed = await createGovernedRedisBackedNonceStore(redis, {
      ...options('checkpoint'),
      expectedEpoch: 'epoch-checkpointed',
    });
    try {
      expect(redis.isQuarantined('checkpoint')).toBe(true);
      expect(() => governed.continuityGuard.assertAcceptable()).toThrow(
        AuthorizationQuarantineError,
      );
      await expect(governed.nonceStore.checkAndConsume('n-checkpoint'))
        .rejects.toMatchObject({ reason: 'continuity_epoch_changed' });
      expect(redis.hasNonce('checkpoint', 'n-checkpoint')).toBe(false);
    } finally {
      await governed.stop();
    }
  });

  it('rejects heterogeneous namespace horizons and preserves the longer quarantine', async () => {
    const redis = new FakeAtomicRedis();
    const fixedNow = Date.now();
    const clock = vi.spyOn(Date, 'now').mockReturnValue(fixedNow);
    let short: Awaited<ReturnType<typeof createGovernedRedisBackedNonceStore>> | undefined;
    try {
      redis.setContinuity('heterogeneous', 'epoch-a', '200:200');
      short = await createGovernedRedisBackedNonceStore(
        redis,
        options('heterogeneous'),
      );
      await expect(createGovernedRedisBackedNonceStore(redis, {
        namespace: 'heterogeneous',
        sigWindowMs: 500,
        safetyBufferMs: 0,
        continuitySafetyAllowanceMs: 0,
        reconcileIntervalMs: 50,
      })).rejects.toBeInstanceOf(RedisContinuityConfigurationError);
      expect(redis.quarantineTtl('heterogeneous')).toBe(1_000);
      await expect(short.nonceStore.checkAndConsume('n-heterogeneous'))
        .rejects.toBeInstanceOf(AuthorizationQuarantineError);
      expect(redis.hasNonce('heterogeneous', 'n-heterogeneous')).toBe(false);
    } finally {
      await short?.stop();
      clock.mockRestore();
    }
  });

  it('rejects malformed shared horizon state and establishes quarantine', async () => {
    const redis = new FakeAtomicRedis();
    redis.setContinuity('bad-config', 'epoch-a', 'not-a-horizon');
    await expect(createGovernedRedisBackedNonceStore(redis, options('bad-config')))
      .rejects.toMatchObject({
        code: 'redis_continuity_config_mismatch',
        status: 'CONFIG_INVALID',
      });
    expect(redis.isQuarantined('bad-config')).toBe(true);
  });

  it('atomically denies an epoch change at consume time without writing the nonce', async () => {
    const redis = new FakeAtomicRedis();
    redis.setContinuity('swap', 'epoch-a');
    const governed = await createGovernedRedisBackedNonceStore(redis, options('swap'));
    try {
      redis.beforeConsume = () => redis.setContinuity('swap', 'epoch-b');
      await expect(governed.nonceStore.checkAndConsume('n-swap')).rejects.toMatchObject({
        code: 'authorization_quarantined',
        reason: 'continuity_epoch_changed',
      });
      expect(redis.hasNonce('swap', 'n-swap')).toBe(false);
      expect(redis.isQuarantined('swap')).toBe(true);
    } finally {
      await governed.stop();
    }
  });

  it('atomically denies continuity deletion at consume time without writing the nonce', async () => {
    const redis = new FakeAtomicRedis();
    redis.setContinuity('missing', 'epoch-a');
    const governed = await createGovernedRedisBackedNonceStore(redis, options('missing'));
    try {
      redis.beforeConsume = () => {
        redis.values.delete(governed.continuityKey);
      };
      await expect(governed.nonceStore.checkAndConsume('n-missing')).rejects.toMatchObject({
        code: 'authorization_quarantined',
        reason: 'continuity_marker_lost',
      });
      expect(redis.hasNonce('missing', 'n-missing')).toBe(false);
    } finally {
      await governed.stop();
    }
  });

  it('fails the local gate closed after Redis outage or malformed script output', async () => {
    const redis = new FakeAtomicRedis();
    redis.setContinuity('outage', 'epoch-a');
    const governed = await createGovernedRedisBackedNonceStore(redis, options('outage'));
    try {
      redis.failConsume = new Error('redis unavailable');
      await expect(governed.nonceStore.checkAndConsume('n-outage'))
        .rejects.toBeInstanceOf(NonceStoreUnavailableError);
      expect(() => governed.continuityGuard.assertAcceptable()).toThrow(AuthorizationQuarantineError);
    } finally {
      await governed.stop();
    }

    const malformedRedis = new FakeAtomicRedis();
    malformedRedis.setContinuity('malformed', 'epoch-a');
    const malformed = await createGovernedRedisBackedNonceStore(
      malformedRedis,
      options('malformed'),
    );
    try {
      malformedRedis.invalidConsumeReply = ['FRESH'];
      await expect(malformed.nonceStore.checkAndConsume('n-malformed'))
        .rejects.toBeInstanceOf(NonceStoreUnavailableError);
      expect(() => malformed.continuityGuard.assertAcceptable())
        .toThrow(AuthorizationQuarantineError);
    } finally {
      await malformed.stop();
    }
  });

  it.each([
    [['FRESH', 'wrong-epoch', '-2']],
    [['FRESH', 'epoch-a', '10']],
    [['QUARANTINED', 'epoch-a', '-2']],
  ])('fails closed on a well-shaped but impossible script reply: %j', async (reply) => {
    const redis = new FakeAtomicRedis();
    redis.setContinuity('impossible', 'epoch-a');
    const governed = await createGovernedRedisBackedNonceStore(redis, options('impossible'));
    try {
      redis.invalidConsumeReply = reply;
      await expect(governed.nonceStore.checkAndConsume('n-impossible'))
        .rejects.toBeInstanceOf(NonceStoreUnavailableError);
      expect(() => governed.continuityGuard.assertAcceptable())
        .toThrow(AuthorizationQuarantineError);
    } finally {
      await governed.stop();
    }
  });

  it('denies a timed-out request even if its Redis EVAL consumes the nonce later', async () => {
    const redis = new LateConsumeRedis();
    redis.setContinuity('late-eval', 'epoch-a');
    const governed = await createGovernedRedisBackedNonceStore(redis, {
      ...options('late-eval'),
      commandTimeoutMs: 10,
    });
    try {
      await expect(governed.nonceStore.checkAndConsume('n-late'))
        .rejects.toBeInstanceOf(NonceStoreUnavailableError);
      expect(() => governed.continuityGuard.assertAcceptable())
        .toThrow(AuthorizationQuarantineError);
      redis.releaseLateCommand?.();
      await redis.lateSettled;
      expect(redis.hasNonce('late-eval', 'n-late')).toBe(true);
      await expect(governed.nonceStore.checkAndConsume('n-late'))
        .rejects.toBeInstanceOf(AuthorizationQuarantineError);
    } finally {
      await governed.stop();
    }
  });

  it('recovers only after the full shared quarantine horizon and reconciliation', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-07-16T00:00:00Z'));
    try {
      const redis = new FakeAtomicRedis();
      const governed = await createGovernedRedisBackedNonceStore(redis, {
        ...options('recovery'),
        sigWindowMs: 20,
        reconcileIntervalMs: 10,
      });
      expect(() => governed.continuityGuard.assertAcceptable()).toThrow(
        AuthorizationQuarantineError,
      );
      await vi.advanceTimersByTimeAsync(39);
      expect(() => governed.continuityGuard.assertAcceptable()).toThrow(
        AuthorizationQuarantineError,
      );
      await vi.advanceTimersByTimeAsync(11);
      expect(() => governed.continuityGuard.assertAcceptable()).not.toThrow();
      await expect(governed.nonceStore.checkAndConsume('n-after')).resolves.toBe(false);
      await governed.stop();
    } finally {
      vi.useRealTimers();
    }
  });

  it('fails the gate closed when periodic policy reconciliation detects drift', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-07-16T00:00:00Z'));
    try {
      const redis = new FakeAtomicRedis();
      redis.setContinuity('drift', 'epoch-a');
      const governed = await createGovernedRedisBackedNonceStore(redis, options('drift'));
      try {
        expect(() => governed.continuityGuard.assertAcceptable()).not.toThrow();
        redis.policy = ['maxmemory-policy', 'allkeys-lru'];
        await vi.advanceTimersByTimeAsync(50);
        expect(() => governed.continuityGuard.assertAcceptable()).toThrow(
          AuthorizationQuarantineError,
        );
      } finally {
        await governed.stop();
      }
    } finally {
      vi.useRealTimers();
    }
  });

  it('fails the gate closed on an impossible periodic reconcile reply', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-07-16T00:00:00Z'));
    try {
      const redis = new FakeAtomicRedis();
      redis.setContinuity('bad-reconcile', 'epoch-a');
      const governed = await createGovernedRedisBackedNonceStore(
        redis,
        options('bad-reconcile'),
      );
      try {
        redis.invalidReconcileReply = ['OK', 'wrong-epoch', '-2'];
        await vi.advanceTimersByTimeAsync(50);
        expect(() => governed.continuityGuard.assertAcceptable())
          .toThrow(AuthorizationQuarantineError);
      } finally {
        await governed.stop();
      }
    } finally {
      vi.useRealTimers();
    }
  });

  it('stop is idempotent and permanently closes its verifier gate', async () => {
    const redis = new FakeAtomicRedis();
    redis.setContinuity('stop', 'epoch-a');
    const governed = await createGovernedRedisBackedNonceStore(redis, options('stop'));
    await Promise.all([governed.stop(), governed.stop()]);
    expect(() => governed.continuityGuard.assertAcceptable()).toThrow(AuthorizationQuarantineError);
    await expect(governed.nonceStore.checkAndConsume('after-stop'))
      .rejects.toBeInstanceOf(AuthorizationQuarantineError);
  });

  it('publishes the named HTTP mapping for continuity quarantine', () => {
    expect(BPC_ERRORS.authorization_quarantined).toEqual({
      code: 'authorization_quarantined',
      message: 'Authorization continuity uncertain',
      httpStatus: 503,
    });
  });
});
