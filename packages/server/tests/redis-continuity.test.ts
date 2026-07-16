import { describe, expect, it } from 'vitest';

import {
  AuthorizationQuarantineError,
  RedisContinuityGuard,
  type RedisContinuityClient,
} from '../src/redis-continuity.js';

/** In-memory marker store; can simulate loss, swap, and outage. */
class FakeMarkerRedis implements RedisContinuityClient {
  private store = new Map<string, string>();
  down = false;

  async get(key: string): Promise<string | null> {
    if (this.down) throw new Error('redis down');
    return this.store.has(key) ? (this.store.get(key) as string) : null;
  }

  async set(key: string, value: string, _nx: 'NX'): Promise<'OK' | null> {
    if (this.down) throw new Error('redis down');
    if (this.store.has(key)) return null;
    this.store.set(key, value);
    return 'OK';
  }

  /** Simulate FLUSHALL / eviction / restore-from-empty. */
  flush(): void {
    this.store.clear();
  }

  /** Simulate failover/restore to a different instance. */
  swapEpoch(key: string, value: string): void {
    this.store.set(key, value);
  }
}

const RETENTION = 130_000;
const ALLOWANCE = 30_000;
const QUARANTINE = RETENTION + ALLOWANCE;

function makeGuard(redis: RedisContinuityClient, clock: { t: number }, epochs?: string[]) {
  let i = 0;
  return new RedisContinuityGuard(redis, {
    namespace: 'test',
    retentionMs: RETENTION,
    safetyAllowanceMs: ALLOWANCE,
    now: () => clock.t,
    newEpoch: epochs ? () => epochs[i++] ?? `auto-${i}` : undefined,
  });
}

describe('RedisContinuityGuard', () => {
  it('fails closed before its first reconciliation', () => {
    const guard = makeGuard(new FakeMarkerRedis(), { t: 1_000 });
    expect(() => guard.assertAcceptable()).toThrow(AuthorizationQuarantineError);
  });

  it('first reconcile with a fresh empty store quarantines (marker was absent)', async () => {
    const redis = new FakeMarkerRedis();
    const clock = { t: 1_000 };
    const guard = makeGuard(redis, clock, ['epoch-A']);
    await guard.reconcile();
    expect(guard.isQuarantined()).toBe(true);
    expect(() => guard.assertAcceptable()).toThrow(AuthorizationQuarantineError);
  });

  it('an established, intact marker does not quarantine', async () => {
    const redis = new FakeMarkerRedis();
    redis.swapEpoch('bpc:test:continuity', 'epoch-existing'); // marker already present
    const clock = { t: 1_000 };
    const guard = makeGuard(redis, clock);
    await guard.reconcile(); // adopts baseline, no quarantine
    expect(guard.isQuarantined()).toBe(false);
    expect(() => guard.assertAcceptable()).not.toThrow();
  });

  it('state loss after baseline quarantines for the full horizon + allowance', async () => {
    const redis = new FakeMarkerRedis();
    redis.swapEpoch('bpc:test:continuity', 'epoch-1');
    const clock = { t: 1_000 };
    const guard = makeGuard(redis, clock, ['epoch-2']);
    await guard.reconcile(); // baseline epoch-1, no quarantine
    expect(guard.isQuarantined()).toBe(false);

    redis.flush(); // FLUSHALL / eviction / restore-empty
    await guard.reconcile();
    expect(guard.isQuarantined()).toBe(true);
    expect(guard.quarantineRemainingMs()).toBe(QUARANTINE);
  });

  it('ambiguous failover (epoch changed under us) quarantines', async () => {
    const redis = new FakeMarkerRedis();
    redis.swapEpoch('bpc:test:continuity', 'epoch-1');
    const clock = { t: 1_000 };
    const guard = makeGuard(redis, clock);
    await guard.reconcile(); // baseline epoch-1
    expect(guard.isQuarantined()).toBe(false);

    redis.swapEpoch('bpc:test:continuity', 'epoch-2'); // failover to other instance
    await guard.reconcile();
    expect(guard.isQuarantined()).toBe(true);
  });

  it('fails CLOSED when the marker store is unreachable', async () => {
    const redis = new FakeMarkerRedis();
    redis.swapEpoch('bpc:test:continuity', 'epoch-1');
    const clock = { t: 1_000 };
    const guard = makeGuard(redis, clock);
    await guard.reconcile();
    expect(guard.isQuarantined()).toBe(false);

    redis.down = true;
    await guard.reconcile(); // unknown continuity => quarantine, never trust
    expect(guard.isQuarantined()).toBe(true);
    expect(() => guard.assertAcceptable()).toThrow(AuthorizationQuarantineError);
  });

  it('quarantine clears only after the full window elapses', async () => {
    const redis = new FakeMarkerRedis();
    const clock = { t: 1_000 };
    const guard = makeGuard(redis, clock, ['epoch-A']);
    await guard.reconcile(); // empty store => quarantine
    expect(guard.isQuarantined()).toBe(true);

    clock.t += QUARANTINE - 1;
    expect(guard.isQuarantined()).toBe(true); // still inside window

    clock.t += 1;
    expect(guard.isQuarantined()).toBe(false); // window elapsed
    expect(() => guard.assertAcceptable()).not.toThrow();
  });

  it('repeated losses extend, never shorten, the quarantine', async () => {
    const redis = new FakeMarkerRedis();
    const clock = { t: 1_000 };
    const guard = makeGuard(redis, clock, ['e1', 'e2']);
    await guard.reconcile(); // empty => quarantine until 1000+QUARANTINE
    const firstUntil = guard.quarantineRemainingMs() + clock.t;

    clock.t += 10_000;
    redis.flush();
    await guard.reconcile(); // new loss extends the window
    const secondUntil = guard.quarantineRemainingMs() + clock.t;
    expect(secondUntil).toBeGreaterThan(firstUntil);
  });

  it('rejects an invalid namespace', () => {
    expect(() => new RedisContinuityGuard(new FakeMarkerRedis(), {
      namespace: 'bad namespace!',
      retentionMs: RETENTION,
    })).toThrow(RangeError);
  });
});
