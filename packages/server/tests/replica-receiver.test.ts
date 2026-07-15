import { describe, expect, it } from 'vitest';

import {
  authorizeReplica,
  handleReplicaIngest,
  validateReplicaOp,
} from '../src/replica-receiver.js';
import {
  MemoryReplicaApplyGuard,
  MemoryReplicaSequenceSource,
  REPLICA_ENVELOPE_VERSION,
  signReplicaEnvelope,
  type ReplicaEnvelope,
} from '../src/replica-envelope.js';
import { ReplicatingPairStore } from '../src/replicating-store.js';
import { MemoryPairStore } from '../src/memory-store.js';
import type { ReplicaOp } from '../src/replicating-store.js';
import type { StoredPair } from '../src/types.js';

const KEY = 'replica-authentication-key-with-32-bytes-minimum';
const SOURCE = 'primary-1';

function pair(id: string, over: Partial<StoredPair> = {}): StoredPair {
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
    ...over,
  } as StoredPair;
}

function signedEnvelope(sequence: number, op: ReplicaOp, sentAt = Date.now()): {
  envelope: ReplicaEnvelope;
  headers: Record<string, string>;
} {
  const envelope: ReplicaEnvelope = {
    version: REPLICA_ENVELOPE_VERSION,
    sourceId: SOURCE,
    sequence,
    sentAt,
    op,
  };
  return {
    envelope,
    headers: { 'x-replica-signature': signReplicaEnvelope(envelope, KEY) },
  };
}

describe('replica envelope authentication and validation', () => {
  it('accepts an authentic envelope and rejects body tampering', () => {
    const { envelope, headers } = signedEnvelope(1, { op: 'set', pair: pair('a') });
    expect(authorizeReplica(headers, envelope, KEY)).toBe(true);
    expect(authorizeReplica(headers, { ...envelope, sequence: 2 }, KEY)).toBe(false);
  });

  it('rejects duplicate signature headers', () => {
    const { envelope, headers } = signedEnvelope(1, { op: 'set', pair: pair('a') });
    expect(authorizeReplica({ 'x-replica-signature': [headers['x-replica-signature'], 'x'] }, envelope, KEY)).toBe(false);
  });

  it('rejects malformed pair state rather than importing it', () => {
    expect(validateReplicaOp({ op: 'set', pair: { ...pair('a'), scope: 'admin:*' } }).ok).toBe(false);
    expect(validateReplicaOp({ op: 'set', pair: { ...pair('a'), status: 'invented' } }).ok).toBe(false);
    expect(validateReplicaOp({ op: 'set', pair: { ...pair('a'), pubJwk: {} } }).ok).toBe(false);
    expect(validateReplicaOp({ op: 'set', pair: { ...pair('a'), maxRequests: 'unlimited' } }).ok).toBe(false);
    expect(validateReplicaOp({ op: 'set', pair: { ...pair('a'), cumulativeFailures: -1 } }).ok).toBe(false);
    expect(validateReplicaOp({ op: 'set', pair: { ...pair('a'), kind: 'ghost' } }).ok).toBe(false);
    expect(validateReplicaOp({
      op: 'set',
      pair: { ...pair('a'), kind: 'legitimate', canaryClass: 'registry_exfil' },
    }).ok).toBe(false);
  });

  it('accepts complete valid authorization state', () => {
    expect(validateReplicaOp({
      op: 'set',
      pair: pair('ghost-a', {
        kind: 'ghost',
        canaryClass: 'registry_exfil',
        maxRequests: 10,
        cumulativeFailures: 1.5,
        firstFailureAt: 1_700_000_000_001,
        expiresAt: 1_800_000_000_000,
      }),
    }).ok).toBe(true);
  });
});

describe('monotonic replica application', () => {
  it('rejects expired authenticated envelopes', async () => {
    const replica = new MemoryPairStore();
    const guard = new MemoryReplicaApplyGuard();
    const now = Date.now();
    const { envelope, headers } = signedEnvelope(1, { op: 'set', pair: pair('a') }, now - 60_001);
    const result = await handleReplicaIngest(replica, headers, envelope, KEY, SOURCE, guard, now);
    expect(result.status).toBe(400);
    expect(result.result.error).toBe('replica_request_expired');
    expect(await replica.get('a')).toBeUndefined();
  });

  it('treats an exact retry as idempotent', async () => {
    const replica = new MemoryPairStore();
    const guard = new MemoryReplicaApplyGuard();
    const request = signedEnvelope(1, { op: 'set', pair: pair('a') });
    expect((await handleReplicaIngest(replica, request.headers, request.envelope, KEY, SOURCE, guard)).status).toBe(200);
    const duplicate = await handleReplicaIngest(replica, request.headers, request.envelope, KEY, SOURCE, guard);
    expect(duplicate.status).toBe(200);
    expect(duplicate.result.error).toBe('duplicate_ignored');
  });

  it('rejects a different operation that reuses an accepted sequence', async () => {
    const replica = new MemoryPairStore();
    const guard = new MemoryReplicaApplyGuard();
    const create = signedEnvelope(1, { op: 'set', pair: pair('a') });
    const conflict = signedEnvelope(1, { op: 'delete', pairId: 'a' });
    expect((await handleReplicaIngest(replica, create.headers, create.envelope, KEY, SOURCE, guard)).status).toBe(200);

    const result = await handleReplicaIngest(replica, conflict.headers, conflict.envelope, KEY, SOURCE, guard);
    expect(result.status).toBe(409);
    expect(result.result.error).toBe('replica_sequence_conflict');
    expect(await replica.get('a')).toBeDefined();
  });

  it('rejects an out-of-order gap without mutating the replica', async () => {
    const replica = new MemoryPairStore();
    const guard = new MemoryReplicaApplyGuard();
    const request = signedEnvelope(2, { op: 'set', pair: pair('a') });
    const result = await handleReplicaIngest(replica, request.headers, request.envelope, KEY, SOURCE, guard);
    expect(result.status).toBe(409);
    expect(result.result.error).toBe('replica_sequence_gap');
    expect(await replica.get('a')).toBeUndefined();
  });

  it('prevents a captured stale set from resurrecting a deleted pair', async () => {
    const replica = new MemoryPairStore();
    const guard = new MemoryReplicaApplyGuard();
    const create = signedEnvelope(1, { op: 'set', pair: pair('a') });
    const remove = signedEnvelope(2, { op: 'delete', pairId: 'a' });

    expect((await handleReplicaIngest(replica, create.headers, create.envelope, KEY, SOURCE, guard)).status).toBe(200);
    expect((await handleReplicaIngest(replica, remove.headers, remove.envelope, KEY, SOURCE, guard)).status).toBe(200);
    expect(await replica.get('a')).toBeUndefined();

    const replay = await handleReplicaIngest(replica, create.headers, create.envelope, KEY, SOURCE, guard);
    expect(replay.status).toBe(409);
    expect(replay.result.error).toBe('replica_sequence_stale');
    expect(await replica.get('a')).toBeUndefined();
  });
});

describe('ReplicatingPairStore to receiver', () => {
  it('converges through authenticated, contiguous envelopes', async () => {
    const primary = new MemoryPairStore();
    const replica = new MemoryPairStore();
    const guard = new MemoryReplicaApplyGuard();
    const fetchImpl = (async (_url: unknown, init: RequestInit) => {
      const body = JSON.parse(String(init.body));
      const headers = Object.fromEntries(Object.entries(init.headers as Record<string, string>));
      const { status } = await handleReplicaIngest(replica, headers, body, KEY, SOURCE, guard);
      return new Response('{}', { status });
    }) as typeof fetch;
    const store = new ReplicatingPairStore(
      primary,
      { url: 'https://replica.test', sourceId: SOURCE, token: KEY },
      { fetchImpl, sequenceSource: new MemoryReplicaSequenceSource() },
    );

    await store.set(pair('a'));
    await store.set(pair('b'));
    await store.delete('b');
    expect(await store.flush()).toBe(true);
    expect(await replica.get('a')).toEqual(await primary.get('a'));
    expect(await replica.get('b')).toBeUndefined();
  });
});
