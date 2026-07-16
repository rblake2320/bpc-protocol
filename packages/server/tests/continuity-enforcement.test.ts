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
  return { config: async () => value as string[] };
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
      const handle = startContinuityReconcileLoop(guard, 1000);
      await vi.advanceTimersByTimeAsync(3500);
      expect(calls).toBe(3);
      handle.stop();
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
      const handle = startContinuityReconcileLoop(guard, 500, (e) => errors.push(e));
      await vi.advanceTimersByTimeAsync(1500);
      expect(calls).toBe(3);
      expect(errors).toHaveLength(3); // loop survived every rejection
      handle.stop();
    } finally {
      vi.useRealTimers();
    }
  });

  it('rejects a non-positive interval', () => {
    expect(() => startContinuityReconcileLoop({ reconcile: async () => {} }, 0)).toThrow(
      RangeError,
    );
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
