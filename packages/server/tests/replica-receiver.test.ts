import { describe, it, expect, beforeEach } from 'vitest';
import {
  authorizeReplica, validateReplicaOp, applyReplicaOp, handleReplicaIngest,
} from '../src/replica-receiver.js';
import { ReplicatingPairStore } from '../src/replicating-store.js';
import { MemoryPairStore } from '../src/memory-store.js';
import type { StoredPair } from '../src/types.js';

function pair(id: string, over: Partial<StoredPair> = {}): StoredPair {
  return {
    id, name: `pair-${id}`, scope: 'read-write', mode: 'development',
    secretHash: 'verifier-not-secret', pubJwk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' },
    status: 'active', created: 1_700_000_000_000, lastActive: null, requests: 0, failedSigs: 0,
    ...over,
  } as StoredPair;
}

const TOKEN = 'replica-shared-token';

describe('replica-receiver auth (RX-01)', () => {
  it('accepts the correct token', () => {
    expect(authorizeReplica({ 'x-replica-token': TOKEN }, TOKEN)).toBe(true);
  });
  it('rejects a wrong token', () => {
    expect(authorizeReplica({ 'x-replica-token': 'nope' }, TOKEN)).toBe(false);
  });
  it('rejects a missing token', () => {
    expect(authorizeReplica({}, TOKEN)).toBe(false);
  });
  it('rejects an array-valued header', () => {
    expect(authorizeReplica({ 'x-replica-token': [TOKEN, 'x'] }, TOKEN)).toBe(true); // first value used
    expect(authorizeReplica({ 'x-replica-token': ['wrong'] }, TOKEN)).toBe(false);
  });
});

describe('replica-receiver op validation (RX-04)', () => {
  it('rejects unknown op', () => {
    expect(validateReplicaOp({ op: 'frobnicate' }).ok).toBe(false);
  });
  it('rejects set without a valid pair id', () => {
    expect(validateReplicaOp({ op: 'set', pair: { name: 'x' } }).ok).toBe(false);
  });
  it('rejects delete without pairId', () => {
    expect(validateReplicaOp({ op: 'delete' }).ok).toBe(false);
  });
  it('accepts a well-formed set', () => {
    const v = validateReplicaOp({ op: 'set', pair: pair('a') });
    expect(v.ok).toBe(true);
  });
});

describe('replica-receiver apply (RX-02 idempotency)', () => {
  let replica: MemoryPairStore;
  beforeEach(() => { replica = new MemoryPairStore(); });

  it('applies set then delete', async () => {
    await applyReplicaOp(replica, { op: 'set', pair: pair('a') });
    expect(await replica.get('a')).toBeDefined();
    await applyReplicaOp(replica, { op: 'delete', pairId: 'a' });
    expect(await replica.get('a')).toBeUndefined();
  });

  it('is idempotent — re-applying set leaves identical state', async () => {
    await applyReplicaOp(replica, { op: 'set', pair: pair('a', { requests: 5 }) });
    await applyReplicaOp(replica, { op: 'set', pair: pair('a', { requests: 5 }) });
    const all = await replica.list();
    expect(all.length).toBe(1);
    expect(all[0].requests).toBe(5);
  });

  it('re-applying delete on an absent pair is a no-op (idempotent)', async () => {
    await applyReplicaOp(replica, { op: 'delete', pairId: 'ghost' });
    await applyReplicaOp(replica, { op: 'delete', pairId: 'ghost' });
    expect((await replica.list()).length).toBe(0);
  });
});

describe('handleReplicaIngest end-to-end status mapping', () => {
  it('401 on bad token, no mutation', async () => {
    const replica = new MemoryPairStore();
    const r = await handleReplicaIngest(replica, { 'x-replica-token': 'bad' }, { op: 'set', pair: pair('a') }, TOKEN);
    expect(r.status).toBe(401);
    expect((await replica.list()).length).toBe(0);
  });
  it('400 on malformed op', async () => {
    const replica = new MemoryPairStore();
    const r = await handleReplicaIngest(replica, { 'x-replica-token': TOKEN }, { op: 'set' }, TOKEN);
    expect(r.status).toBe(400);
  });
  it('200 on a good op', async () => {
    const replica = new MemoryPairStore();
    const r = await handleReplicaIngest(replica, { 'x-replica-token': TOKEN }, { op: 'set', pair: pair('a') }, TOKEN);
    expect(r.status).toBe(200);
    expect(await replica.get('a')).toBeDefined();
  });
});

describe('END-TO-END: ReplicatingPairStore -> wire -> receiver -> replica matches primary', () => {
  it('replica store converges to the primary store', async () => {
    const primary = new MemoryPairStore();
    const replica = new MemoryPairStore();

    // fetchImpl routes the decorator's HTTP push straight into the receiver,
    // simulating the VPS ingest endpoint in-process.
    const fetchImpl = (async (_url: any, init: any) => {
      const body = JSON.parse(init.body);
      const headers = Object.fromEntries(Object.entries(init.headers));
      const { status } = await handleReplicaIngest(replica, headers, body, TOKEN);
      return new Response('{}', { status });
    }) as unknown as typeof fetch;

    const store = new ReplicatingPairStore(primary, { url: 'https://vps/replica', token: TOKEN }, { fetchImpl });

    await store.set(pair('a', { requests: 1 }));
    await store.set(pair('b', { requests: 2 }));
    await store.setPending('tok-1', { name: 'pending-x' } as any, 1_700_000_000_001);
    await store.set(pair('a', { requests: 99 }));   // update
    await store.delete('b');
    await store.deletePending('tok-1');
    const drained = await store.flush(3000);
    expect(drained).toBe(true);

    // Replica must now mirror the primary exactly.
    const primaryPairs = (await primary.list()).sort((x, y) => x.id.localeCompare(y.id));
    const replicaPairs = (await replica.list()).sort((x, y) => x.id.localeCompare(y.id));
    expect(replicaPairs).toEqual(primaryPairs);
    expect(replicaPairs.length).toBe(1);          // only 'a' remains
    expect(replicaPairs[0].requests).toBe(99);    // update propagated
    expect(await replica.getPending('tok-1')).toBeUndefined();  // pending deleted
  });
});
