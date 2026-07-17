import { describe, expect, it } from 'vitest';

import {
  CheckpointConflictError,
  CheckpointInconsistentError,
  CheckpointUnavailableError,
  MonotonicCheckpoint,
  RollbackCheckpointGuard,
  RollbackDetectedError,
  type CheckpointState,
} from '../src/rollback-checkpoint.js';

/**
 * In-memory witness that can simulate the adversarial conditions. NOTE (per
 * issue #15): a fake CANNOT close the issue — it only proves the guard LOGIC.
 * The real control requires a fenced PostgreSQL row + a live Redis rollback
 * drill. These tests validate the mechanism's fail-closed decisions only.
 */
class FakeWitness implements MonotonicCheckpoint {
  private store = new Map<string, CheckpointState>();
  down = false;

  async read(ns: string): Promise<CheckpointState | null> {
    if (this.down) throw new Error('witness unreachable');
    const s = this.store.get(ns);
    return s ? { ...s } : null;
  }

  async compareAndAdvance(
    ns: string,
    expected: CheckpointState | null,
    next: CheckpointState,
  ): Promise<CheckpointState> {
    if (this.down) throw new Error('witness unreachable');
    const cur = this.store.get(ns) ?? null;
    if (!sameState(cur, expected)) throw new CheckpointConflictError();
    this.store.set(ns, { ...next });
    return { ...next };
  }

  /** Test helper: force the authoritative sequence (simulate it having advanced). */
  force(ns: string, state: CheckpointState): void {
    this.store.set(ns, { ...state });
  }
}

function sameState(a: CheckpointState | null, b: CheckpointState | null): boolean {
  if (a === null || b === null) return a === b;
  return a.epoch === b.epoch && a.sequence === b.sequence;
}

const NS = 'test';
const guardFor = (w: MonotonicCheckpoint) => new RollbackCheckpointGuard(w, { namespace: NS });

describe('RollbackCheckpointGuard (#15 mechanism)', () => {
  it('bootstraps the witness on first use and advances by one', async () => {
    const w = new FakeWitness();
    const g = guardFor(w);
    const seq = await g.verifyAndAdvance({ epoch: 'e1', sequence: 0 });
    expect(seq).toBe(1);
    expect(await w.read(NS)).toEqual({ epoch: 'e1', sequence: 1 });
  });

  it('advances monotonically across a run of accepts', async () => {
    const w = new FakeWitness();
    const g = guardFor(w);
    let redisSeq = 0;
    for (let i = 1; i <= 5; i++) {
      const s = await g.verifyAndAdvance({ epoch: 'e1', sequence: redisSeq });
      expect(s).toBe(i);
      redisSeq = s; // caller mirrors it back into Redis
    }
  });

  it('DETECTS a same-epoch rollback (Redis behind the witness) and fails closed', async () => {
    const w = new FakeWitness();
    const g = guardFor(w);
    // Accept a few; witness + Redis both reach 3.
    let redisSeq = 0;
    for (let i = 0; i < 3; i++) redisSeq = await g.verifyAndAdvance({ epoch: 'e1', sequence: redisSeq });
    expect(redisSeq).toBe(3);
    // Redis is snapshot-restored to an OLDER same-epoch state (sequence 1),
    // while the independent witness retains 3.
    await expect(
      g.verifyAndAdvance({ epoch: 'e1', sequence: 1 }),
    ).rejects.toBeInstanceOf(RollbackDetectedError);
  });

  it('fails closed when the witness is unavailable', async () => {
    const w = new FakeWitness();
    const g = guardFor(w);
    w.down = true;
    await expect(
      g.verifyAndAdvance({ epoch: 'e1', sequence: 0 }),
    ).rejects.toBeInstanceOf(CheckpointUnavailableError);
  });

  it('fails closed when Redis and the witness disagree on epoch', async () => {
    const w = new FakeWitness();
    w.force(NS, { epoch: 'e1', sequence: 2 });
    const g = guardFor(w);
    await expect(
      g.verifyAndAdvance({ epoch: 'DIFFERENT', sequence: 5 }),
    ).rejects.toBeInstanceOf(CheckpointInconsistentError);
  });

  it('fails closed on a concurrent-writer fencing conflict', async () => {
    const w = new FakeWitness();
    w.force(NS, { epoch: 'e1', sequence: 2 });
    const g = guardFor(w);
    // Another writer advances the witness between this guard's read and CAS.
    const original = w.compareAndAdvance.bind(w);
    let raced = false;
    (w as unknown as { compareAndAdvance: MonotonicCheckpoint['compareAndAdvance'] }).compareAndAdvance =
      async (ns, expected, next) => {
        if (!raced) {
          raced = true;
          w.force(NS, { epoch: 'e1', sequence: 3 }); // someone else moved it
        }
        return original(ns, expected, next);
      };
    await expect(
      g.verifyAndAdvance({ epoch: 'e1', sequence: 2 }),
    ).rejects.toBeInstanceOf(CheckpointConflictError);
  });

  it('a witness that survives a verifier restart still detects the rollback', async () => {
    const w = new FakeWitness();
    // Guard instance 1 accepts to sequence 2.
    let redisSeq = 0;
    const g1 = guardFor(w);
    for (let i = 0; i < 2; i++) redisSeq = await g1.verifyAndAdvance({ epoch: 'e1', sequence: redisSeq });
    // "Restart": brand-new guard instance, same durable witness. Redis rolled
    // back to sequence 0 during the outage.
    const g2 = guardFor(w);
    await expect(
      g2.verifyAndAdvance({ epoch: 'e1', sequence: 0 }),
    ).rejects.toBeInstanceOf(RollbackDetectedError);
  });

  it('accepts normally when Redis is at or ahead of the witness', async () => {
    const w = new FakeWitness();
    w.force(NS, { epoch: 'e1', sequence: 4 });
    const g = guardFor(w);
    // Redis exactly matches -> advance to 5.
    expect(await g.verifyAndAdvance({ epoch: 'e1', sequence: 4 })).toBe(5);
  });
});
