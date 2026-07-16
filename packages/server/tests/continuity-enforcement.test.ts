import { describe, expect, it, vi } from 'vitest';

import {
  EvictionPolicyError,
  assertNoEvictionPolicy,
  startContinuityReconcileLoop,
  type ContinuityGate,
  type RedisConfigClient,
} from '../src/redis-continuity.js';
import { AuthorizationQuarantineError } from '../src/redis-continuity.js';

// ---- (1) noeviction assertion at startup -----------------------------------

function configReturning(value: unknown): RedisConfigClient {
  return { config: async () => value };
}

describe('assertNoEvictionPolicy', () => {
  it('accepts noeviction (ioredis array shape)', async () => {
    await expect(
      assertNoEvictionPolicy(configReturning(['maxmemory-policy', 'noeviction'])),
    ).resolves.toBeUndefined();
  });

  it('accepts noeviction (map shape)', async () => {
    await expect(
      assertNoEvictionPolicy(configReturning({ 'maxmemory-policy': 'noeviction' })),
    ).resolves.toBeUndefined();
  });

  it.each(['allkeys-lru', 'volatile-lru', 'allkeys-random', 'volatile-ttl'])(
    'rejects eviction-capable policy %s',
    async (policy) => {
      await expect(
        assertNoEvictionPolicy(configReturning(['maxmemory-policy', policy])),
      ).rejects.toBeInstanceOf(EvictionPolicyError);
    },
  );

  it('rejects an unreadable/empty policy (fail closed)', async () => {
    await expect(assertNoEvictionPolicy(configReturning([]))).rejects.toBeInstanceOf(
      EvictionPolicyError,
    );
  });

  it.each([
    [['wrong-key', 'noeviction']],
    [['maxmemory-policy', 'noeviction', 'extra']],
    [['maxmemory-policy', 1]],
    [{ 'wrong-key': 'noeviction' }],
    [{ 'maxmemory-policy': 'noeviction', extra: 'value' }],
    [{ 'maxmemory-policy': 1 }],
  ])('rejects malformed or ambiguous CONFIG responses: %j', async (raw) => {
    await expect(assertNoEvictionPolicy(configReturning(raw))).rejects.toMatchObject({
      code: 'redis_eviction_policy_unsafe',
      policy: 'unknown',
    });
  });

  it('rethrows if CONFIG GET itself fails (fail closed)', async () => {
    const redis: RedisConfigClient = {
      config: async () => {
        throw new Error('redis down');
      },
    };
    await expect(assertNoEvictionPolicy(redis)).rejects.toThrow('redis down');
  });
});

// ---- (3) periodic reconcile tick -------------------------------------------

describe('startContinuityReconcileLoop', () => {
  it('calls reconcile on each interval and stops cleanly', async () => {
    vi.useFakeTimers();
    try {
      let calls = 0;
      const guard = { reconcile: async () => { calls += 1; } };
      const handle = startContinuityReconcileLoop(guard, {
        intervalMs: 1000,
        retentionMs: 10_000,
      });
      await vi.advanceTimersByTimeAsync(3500);
      expect(calls).toBe(3);
      await handle.stop();
      await vi.advanceTimersByTimeAsync(5000);
      expect(calls).toBe(3); // no ticks after stop
    } finally {
      vi.useRealTimers();
    }
  });

  it('swallows reconcile errors via onError and keeps ticking', async () => {
    vi.useFakeTimers();
    try {
      const errors: unknown[] = [];
      let calls = 0;
      const guard = {
        reconcile: async () => {
          calls += 1;
          throw new Error(`boom ${calls}`);
        },
      };
      const handle = startContinuityReconcileLoop(guard, {
        intervalMs: 500,
        retentionMs: 10_000,
        onError: (e) => errors.push(e),
      });
      await vi.advanceTimersByTimeAsync(1500);
      expect(calls).toBe(3);
      expect(errors).toHaveLength(3); // loop survived every rejection
      await handle.stop();
    } finally {
      vi.useRealTimers();
    }
  });

  it('rejects a non-positive interval', () => {
    expect(() => startContinuityReconcileLoop(
      { reconcile: async () => {} },
      { intervalMs: 0, retentionMs: 1000 },
    )).toThrow(RangeError);
  });

  it('rejects a cadence that is not shorter than nonce retention', () => {
    expect(() => startContinuityReconcileLoop(
      { reconcile: async () => {} },
      { intervalMs: 1000, retentionMs: 1000 },
    )).toThrow(RangeError);
  });

  it('serializes reconciliation and stop waits for the active tick', async () => {
    vi.useFakeTimers();
    try {
      let calls = 0;
      let active = 0;
      let maxActive = 0;
      let release: (() => void) | undefined;
      const blocked = new Promise<void>((resolve) => { release = resolve; });
      const handle = startContinuityReconcileLoop({
        reconcile: async () => {
          calls += 1;
          active += 1;
          maxActive = Math.max(maxActive, active);
          await blocked;
          active -= 1;
        },
      }, { intervalMs: 100, retentionMs: 1000 });

      await vi.advanceTimersByTimeAsync(500);
      expect(calls).toBe(1);
      expect(maxActive).toBe(1);
      const stopped = handle.stop();
      let stopResolved = false;
      void stopped.then(() => { stopResolved = true; });
      await Promise.resolve();
      expect(stopResolved).toBe(false);
      release?.();
      await stopped;
      expect(active).toBe(0);
      await vi.advanceTimersByTimeAsync(1000);
      expect(calls).toBe(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it('contains observer failures and continues reconciling', async () => {
    vi.useFakeTimers();
    try {
      let calls = 0;
      const handle = startContinuityReconcileLoop({
        reconcile: async () => {
          calls += 1;
          throw new Error('store unavailable');
        },
      }, {
        intervalMs: 100,
        retentionMs: 1000,
        onError: () => { throw new Error('observer failed'); },
      });
      await vi.advanceTimersByTimeAsync(350);
      expect(calls).toBe(3);
      await handle.stop();
    } finally {
      vi.useRealTimers();
    }
  });
});

// ---- (2) wiring seam: a quarantined gate throws for the middleware ----------

describe('ContinuityGate contract used by the verifier path', () => {
  it('a quarantined gate throws AuthorizationQuarantineError', () => {
    const quarantined: ContinuityGate = {
      assertAcceptable() {
        throw new AuthorizationQuarantineError('continuity_marker_lost', 1);
      },
    };
    expect(() => quarantined.assertAcceptable()).toThrow(AuthorizationQuarantineError);
  });

  it('an acceptable gate does not throw', () => {
    const ok: ContinuityGate = { assertAcceptable() {} };
    expect(() => ok.assertAcceptable()).not.toThrow();
  });
});
