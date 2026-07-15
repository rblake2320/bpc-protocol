import { describe, it, expect } from 'vitest';
import { FailoverTransport, PrimaryUnavailableError } from '../src/failover-transport.js';

/**
 * Scriptable fake fetch keyed by URL prefix. Each endpoint can be flipped
 * up/down at runtime to drive failover/fail-back.
 */
function makeNet() {
  const up: Record<string, boolean> = {};
  const hits: string[] = [];
  const impl = (async (url: any) => {
    const u = String(url);
    hits.push(u);
    const base = Object.keys(up).find((b) => u.startsWith(b));
    if (base && up[base]) return new Response('{}', { status: 200 });
    throw new Error(`network down: ${u}`);
  }) as unknown as typeof fetch;
  return {
    impl, hits,
    set: (base: string, isUp: boolean) => { up[base] = isUp; },
  };
}

const PRIMARY = 'https://primary.test';
const REPLICA = 'https://replica.test';

describe('FT-02 writes are primary-only', () => {
  it('writes go to the primary when it is healthy', async () => {
    const net = makeNet(); net.set(PRIMARY, true); net.set(REPLICA, true);
    const t = new FailoverTransport({ primary: PRIMARY, replicas: [REPLICA], fetchImpl: net.impl });
    const res = await t.write('/bpc/register', { body: '{}' });
    expect(res.status).toBe(200);
    expect(net.hits.every((h) => h.startsWith(PRIMARY))).toBe(true);  // never hit replica
  });

  it('throws PrimaryUnavailableError instead of writing to a replica (split-brain guard)', async () => {
    const net = makeNet(); net.set(PRIMARY, false); net.set(REPLICA, true);
    const t = new FailoverTransport({ primary: PRIMARY, replicas: [REPLICA], missThreshold: 1, fetchImpl: net.impl });
    // Trip the primary unhealthy via a failed write attempt first.
    await expect(t.write('/x', {})).rejects.toThrow();           // network error trips miss → unhealthy
    await expect(t.write('/x', {})).rejects.toBeInstanceOf(PrimaryUnavailableError);
    // The replica was never used for a write.
    expect(net.hits.some((h) => h.startsWith(REPLICA))).toBe(false);
  });
});

describe('FT-01 reads fail over and stay sticky', () => {
  it('reads use the primary while healthy', async () => {
    const net = makeNet(); net.set(PRIMARY, true); net.set(REPLICA, true);
    const t = new FailoverTransport({ primary: PRIMARY, replicas: [REPLICA], fetchImpl: net.impl });
    await t.read('/status');
    expect(t.activeReadUrl).toBe(PRIMARY);
    expect(net.hits[0].startsWith(PRIMARY)).toBe(true);
  });

  it('after missThreshold consecutive misses, reads fail over to the replica', async () => {
    const net = makeNet(); net.set(PRIMARY, false); net.set(REPLICA, true);
    const t = new FailoverTransport({ primary: PRIMARY, replicas: [REPLICA], missThreshold: 3, fetchImpl: net.impl });
    // Each read attempt: primary fails (miss), then falls through to replica (success).
    for (let i = 0; i < 3; i++) await t.read('/status');
    expect(t.primaryHealthy).toBe(false);           // primary marked down
    expect(t.activeReadUrl).toBe(REPLICA);          // sticky to replica
  });

  it('a single read still succeeds via replica even before the threshold trips', async () => {
    const net = makeNet(); net.set(PRIMARY, false); net.set(REPLICA, true);
    const t = new FailoverTransport({ primary: PRIMARY, replicas: [REPLICA], missThreshold: 3, fetchImpl: net.impl });
    const res = await t.read('/status');
    expect(res.status).toBe(200);                   // served by replica despite primary down
  });
});

describe('FT-03 auto fail-back on health probe', () => {
  it('a passing primary probe restores the primary and reads fail back to it', async () => {
    const net = makeNet(); net.set(PRIMARY, false); net.set(REPLICA, true);
    const t = new FailoverTransport({ primary: PRIMARY, replicas: [REPLICA], missThreshold: 1, fetchImpl: net.impl });
    await t.read('/status');                        // trips primary unhealthy (threshold 1)
    expect(t.primaryHealthy).toBe(false);

    net.set(PRIMARY, true);                          // primary recovers
    const ok = await t.probePrimary();
    expect(ok).toBe(true);
    expect(t.primaryHealthy).toBe(true);             // failed back
    expect(t.activeReadUrl).toBe(PRIMARY);
  });
});

describe('miss window aging', () => {
  it('a success resets the miss streak so old misses do not accumulate', async () => {
    const net = makeNet(); net.set(PRIMARY, true); net.set(REPLICA, true);
    const t = new FailoverTransport({ primary: PRIMARY, replicas: [REPLICA], missThreshold: 3, fetchImpl: net.impl });
    net.set(PRIMARY, false); await t.read('/a').catch(() => {});  // miss 1 (then replica serves)
    net.set(PRIMARY, true);  await t.read('/b');                  // success resets streak
    net.set(PRIMARY, false); await t.read('/c');                  // miss 1 again, not 2
    expect(t.primaryHealthy).toBe(true);                          // still healthy (streak never hit 3)
  });
});
