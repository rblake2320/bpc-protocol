import { describe, expect, it } from 'vitest';

import {
  CheckpointConflictError,
  CheckpointInconsistentError,
  CheckpointUnavailableError,
  MalformedCasError,
  MonotonicCheckpoint,
  NotAuthorizedError,
  RedisAheadError,
  RollbackCheckpointGuard,
  RollbackDetectedError,
  SequenceExhaustedError,
  WitnessMissingError,
  type CheckpointState,
  type ProvisioningAuthorizer,
} from '../src/rollback-checkpoint.js';

const ALLOW: ProvisioningAuthorizer = { async authorizeProvision() { return true; } };
const DENY: ProvisioningAuthorizer = { async authorizeProvision() { return false; } };
const AUTHORIZER_DOWN: ProvisioningAuthorizer = { async authorizeProvision() { throw new Error('authorizer unavailable'); } };

/**
 * In-memory witness — proves the primitive's LOGIC only. Per #15 a fake cannot
 * close the issue; the real control needs a fenced PostgreSQL row + a live
 * Redis rollback drill.
 */
class FakeWitness implements MonotonicCheckpoint {
  private store = new Map<string, CheckpointState>();
  down = false;
  /** Optional hook to corrupt the CAS return (malformed-CAS test). */
  casOverride: ((next: CheckpointState) => CheckpointState) | null = null;

  async read(ns: string): Promise<CheckpointState | null> {
    if (this.down) throw new Error('witness unreachable');
    const s = this.store.get(ns);
    return s ? { ...s } : null;
  }
  async compareAndAdvance(ns: string, expected: CheckpointState | null, next: CheckpointState): Promise<CheckpointState> {
    if (this.down) throw new Error('witness unreachable');
    const cur = this.store.get(ns) ?? null;
    if (!sameState(cur, expected)) throw new CheckpointConflictError();
    const persisted = this.casOverride ? this.casOverride(next) : { ...next };
    this.store.set(ns, { ...next });
    return { ...persisted };
  }
  async createGenesis(ns: string, genesis: CheckpointState): Promise<CheckpointState> {
    if (this.down) throw new Error('witness unreachable');
    if (this.store.has(ns)) throw new CheckpointConflictError();
    this.store.set(ns, { ...genesis });
    return { ...genesis };
  }
  force(ns: string, s: CheckpointState): void { this.store.set(ns, { ...s }); }
  delete(ns: string): void { this.store.delete(ns); }
}
function sameState(a: CheckpointState | null, b: CheckpointState | null): boolean {
  if (a === null || b === null) return a === b;
  return a.epoch === b.epoch && a.sequence === b.sequence;
}

const NS = 'test';
const guardFor = (w: MonotonicCheckpoint, authorizer: ProvisioningAuthorizer = ALLOW) => new RollbackCheckpointGuard(w, { namespace: NS, authorizer });

describe('RollbackCheckpointGuard (#15 detection + reservation)', () => {
  it('HIGH2: no silent re-anchor — missing witness fails closed on check and reserve', async () => {
    const w = new FakeWitness();
    const g = guardFor(w);
    expect(await g.check({ epoch: 'e1', sequence: 0 })).toBe('witness-missing');
    await expect(g.reserve({ epoch: 'e1', sequence: 0 })).rejects.toBeInstanceOf(WitnessMissingError);
  });

  it('re-review A: provisioning is gated by the injected authorizer, not a string', async () => {
    // deny
    await expect(guardFor(new FakeWitness(), DENY).provision('e1')).rejects.toBeInstanceOf(NotAuthorizedError);
    // allow
    const w = new FakeWitness();
    const genesis = await guardFor(w, ALLOW).provision('e1');
    expect(genesis).toEqual({ epoch: 'e1', sequence: 0 });
    // re-provision refused (row exists)
    await expect(guardFor(w, ALLOW).provision('e1')).rejects.toBeInstanceOf(CheckpointConflictError);
  });

  it('re-review A: authorizer unavailable fails closed (CheckpointUnavailableError)', async () => {
    await expect(guardFor(new FakeWitness(), AUTHORIZER_DOWN).provision('e1'))
      .rejects.toBeInstanceOf(CheckpointUnavailableError);
  });

  it('provision witness outage fails closed (CheckpointUnavailableError)', async () => {
    const w = new FakeWitness(); w.down = true;
    await expect(guardFor(w, ALLOW).provision('e1')).rejects.toBeInstanceOf(CheckpointUnavailableError);
  });

  it('constructor requires a ProvisioningAuthorizer', () => {
    expect(() => new RollbackCheckpointGuard(new FakeWitness(), { namespace: NS } as never)).toThrow();
  });

  it('HIGH1: steady state requires EXACT equality; reserve advances by one', async () => {
    const w = new FakeWitness();
    const g = guardFor(w);
    await g.provision('e1'); // witness at seq 0
    expect(await g.check({ epoch: 'e1', sequence: 0 })).toBe('ok');
    expect(await g.reserve({ epoch: 'e1', sequence: 0 })).toBe(1);
    expect(await g.reserve({ epoch: 'e1', sequence: 1 })).toBe(2);
  });

  it('HIGH1: redis BEHIND witness = rollback (redis=1 witness=3)', async () => {
    const w = new FakeWitness(); w.force(NS, { epoch: 'e1', sequence: 3 });
    const g = guardFor(w);
    expect(await g.check({ epoch: 'e1', sequence: 1 })).toBe('rollback');
    await expect(g.reserve({ epoch: 'e1', sequence: 1 })).rejects.toBeInstanceOf(RollbackDetectedError);
  });

  it('HIGH1: redis AHEAD of witness is ALSO an anomaly (redis=10 witness=4)', async () => {
    const w = new FakeWitness(); w.force(NS, { epoch: 'e1', sequence: 4 });
    const g = guardFor(w);
    expect(await g.check({ epoch: 'e1', sequence: 10 })).toBe('redis-ahead');
    await expect(g.reserve({ epoch: 'e1', sequence: 10 })).rejects.toBeInstanceOf(RedisAheadError);
  });

  it('epoch mismatch fails closed', async () => {
    const w = new FakeWitness(); w.force(NS, { epoch: 'e1', sequence: 2 });
    const g = guardFor(w);
    expect(await g.check({ epoch: 'DIFFERENT', sequence: 2 })).toBe('epoch-mismatch');
    await expect(g.reserve({ epoch: 'DIFFERENT', sequence: 2 })).rejects.toBeInstanceOf(CheckpointInconsistentError);
  });

  it('witness outage fails closed', async () => {
    const w = new FakeWitness(); w.force(NS, { epoch: 'e1', sequence: 1 });
    const g = guardFor(w); w.down = true;
    await expect(g.check({ epoch: 'e1', sequence: 1 })).rejects.toBeInstanceOf(CheckpointUnavailableError);
    await expect(g.reserve({ epoch: 'e1', sequence: 1 })).rejects.toBeInstanceOf(CheckpointUnavailableError);
  });

  it('concurrent-writer fencing conflict fails closed', async () => {
    const w = new FakeWitness(); w.force(NS, { epoch: 'e1', sequence: 2 });
    const g = guardFor(w);
    const orig = w.compareAndAdvance.bind(w);
    let raced = false;
    (w as unknown as { compareAndAdvance: MonotonicCheckpoint['compareAndAdvance'] }).compareAndAdvance =
      async (ns, expected, next) => { if (!raced) { raced = true; w.force(NS, { epoch: 'e1', sequence: 3 }); } return orig(ns, expected, next); };
    await expect(g.reserve({ epoch: 'e1', sequence: 2 })).rejects.toBeInstanceOf(CheckpointConflictError);
  });

  it('MED4: malformed CAS return (store lies) fails closed', async () => {
    const w = new FakeWitness(); w.force(NS, { epoch: 'e1', sequence: 2 });
    w.casOverride = () => ({ epoch: 'e1', sequence: 99 }); // returns wrong state
    const g = guardFor(w);
    await expect(g.reserve({ epoch: 'e1', sequence: 2 })).rejects.toBeInstanceOf(MalformedCasError);
  });

  it('MED4: sequence exhaustion forces governed rotation', async () => {
    const w = new FakeWitness();
    const near = Number.MAX_SAFE_INTEGER - 1;
    w.force(NS, { epoch: 'e1', sequence: near });
    const g = guardFor(w);
    await expect(g.reserve({ epoch: 'e1', sequence: near })).rejects.toBeInstanceOf(SequenceExhaustedError);
  });

  it('MED4: invalid ids / sequences are rejected', async () => {
    const w = new FakeWitness();
    expect(() => new RollbackCheckpointGuard(w, { namespace: 'bad ns', authorizer: ALLOW })).toThrow();
    const g = guardFor(w);
    await expect(g.check({ epoch: 'bad epoch', sequence: 0 })).rejects.toBeTruthy();
    await expect(g.check({ epoch: 'e1', sequence: -1 })).rejects.toBeTruthy();
  });

  it('HIGH2 deletion regression: deleting the trust row after use fails closed (no re-anchor)', async () => {
    const w = new FakeWitness();
    const g = guardFor(w);
    await g.provision('e1');
    await g.reserve({ epoch: 'e1', sequence: 0 }); // witness -> 1
    w.delete(NS); // external trust row deleted
    // Redis rolled back to 0; without the row a naive impl would re-anchor. We fail closed.
    expect(await g.check({ epoch: 'e1', sequence: 0 })).toBe('witness-missing');
    await expect(g.reserve({ epoch: 'e1', sequence: 0 })).rejects.toBeInstanceOf(WitnessMissingError);
  });

  it('reservation-before-commit crash leaves witness ahead -> detected as rollback next time', async () => {
    const w = new FakeWitness();
    const g = guardFor(w);
    await g.provision('e1');
    const reserved = await g.reserve({ epoch: 'e1', sequence: 0 }); // witness -> 1
    expect(reserved).toBe(1);
    // "crash" before the caller mirrors 1 into Redis; Redis still shows 0.
    expect(await g.check({ epoch: 'e1', sequence: 0 })).toBe('rollback');
  });
});
