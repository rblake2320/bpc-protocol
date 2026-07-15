import { describe, it, expect, beforeEach, vi } from 'vitest';
import { ReplicatingPairStore } from '../src/replicating-store.js';
import type { ReplicaOp } from '../src/replicating-store.js';
import { MemoryPairStore } from '../src/memory-store.js';
import type { StoredPair } from '../src/types.js';
import { MemoryReplicaSequenceSource } from '../src/replica-envelope.js';
import type { ReplicaEnvelope } from '../src/replica-envelope.js';

function pair(id: string): StoredPair {
  return {
    id,
    name: `pair-${id}`,
    scope: 'read-write',
    mode: 'development',
    secretHash: 'A'.repeat(43),
    pubJwk: { kty: 'EC', crv: 'P-256', x: 'A'.repeat(43), y: 'B'.repeat(43) },
    status: 'active',
    created: 1_700_000_000_000,
    lastActive: null,
    requests: 0,
    failedSigs: 0,
  } as StoredPair;
}

/** Captures the bodies POSTed to the replica. */
function makeFetch(behavior: () => Response | Promise<Response>) {
  const calls: any[] = [];
  const impl = (async (url: any, init: any) => {
    calls.push({ url, body: JSON.parse(init.body) });
    return behavior();
  }) as unknown as typeof fetch;
  return { impl, calls };
}

const OK = () => new Response('{}', { status: 200 });
const FAIL = () => new Response('err', { status: 503 });
const TARGET = { url: 'https://replica.test/replica', sourceId: 'primary-1', token: 't'.repeat(32) };
const options = () => ({ sequenceSource: new MemoryReplicaSequenceSource() });

describe('ReplicatingPairStore', () => {
  let primary: MemoryPairStore;
  beforeEach(() => { primary = new MemoryPairStore(); });

  it('HA-01: primary write succeeds and is authoritative before replica is touched', async () => {
    const { impl } = makeFetch(OK);
    const store = new ReplicatingPairStore(
      primary, TARGET, { ...options(), fetchImpl: impl },
    );
    await store.set(pair('a'));
    // Primary has it immediately — read path hits primary.
    expect(await store.get('a')).toBeDefined();
    expect((await store.get('a'))!.id).toBe('a');
  });

  it('mirrors set/delete to the replica with op envelopes', async () => {
    const { impl, calls } = makeFetch(OK);
    const store = new ReplicatingPairStore(
      primary, TARGET, { ...options(), fetchImpl: impl },
    );
    await store.set(pair('a'));
    await store.delete('a');
    await store.flush();

    expect(calls.length).toBe(2);
    expect(calls[0].url).toBe('https://replica.test/replica/pair');
    expect((calls[0].body as ReplicaEnvelope).op.op).toBe('set');
    expect((calls[1].body as ReplicaEnvelope).op.op).toBe('delete');
    expect((calls[0].body as ReplicaEnvelope).sequence).toBe(1);
    expect((calls[1].body as ReplicaEnvelope).sequence).toBe(2);
  });

  it('HA-01: replica failure NEVER fails or blocks the primary write', async () => {
    const { impl } = makeFetch(FAIL);
    const store = new ReplicatingPairStore(
      primary, TARGET,
      { ...options(), fetchImpl: impl, backoffBaseMs: 1, backoffMaxMs: 2 },
    );
    // Should resolve fine despite the replica returning 503.
    await expect(store.set(pair('a'))).resolves.toBeUndefined();
    expect(await store.get('a')).toBeDefined();
  });

  it('retries failed pushes then succeeds (queue head preserved on failure)', async () => {
    let n = 0;
    const { impl, calls } = makeFetch(() => (++n < 3 ? FAIL() : OK()));
    const store = new ReplicatingPairStore(
      primary, TARGET,
      { ...options(), fetchImpl: impl, backoffBaseMs: 1, backoffMaxMs: 2 },
    );
    await store.set(pair('a'));
    const flushed = await store.flush(2000);
    expect(flushed).toBe(true);
    expect(calls.length).toBe(3);          // 2 failures + 1 success
    expect(store.queueDepth).toBe(0);
  });

  it('HA-02: bounded queue sheds OLDEST and fires onDrop (no memory exhaustion)', async () => {
    const dropped: ReplicaOp[] = [];
    // Replica permanently down so nothing drains.
    const { impl } = makeFetch(FAIL);
    const store = new ReplicatingPairStore(
      primary, TARGET,
      { ...options(), fetchImpl: impl, maxQueue: 3, backoffBaseMs: 10_000, backoffMaxMs: 10_000,
        onDrop: (op) => dropped.push(op) },
    );
    for (const id of ['a', 'b', 'c', 'd', 'e']) await store.set(pair(id));
    // Queue capped at 3; oldest (a, b) shed.
    expect(store.queueDepth).toBeLessThanOrEqual(3);
    expect(dropped.length).toBeGreaterThanOrEqual(1);
    expect((dropped[0] as any).pair.id).toBe('a');  // oldest shed first
  });

  it('reads are served from primary, never the replica', async () => {
    const { impl, calls } = makeFetch(OK);
    const store = new ReplicatingPairStore(
      primary, TARGET, { ...options(), fetchImpl: impl },
    );
    await store.set(pair('a'));
    await store.flush();
    const before = calls.length;
    await store.get('a');
    await store.list();
    expect(calls.length).toBe(before);   // no replica traffic for reads
  });
});
