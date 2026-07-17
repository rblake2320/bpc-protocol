/**
 * Same-epoch rollback detection via an independent monotonic checkpoint — #15.
 *
 * The continuity guard (redis-continuity.ts) detects a MISSING marker (total
 * state loss) or a CHANGED epoch (failover/restore to another instance). It
 * cannot detect a *same-epoch rollback*: a Redis snapshot/AOF or replica
 * restored to an older internally-consistent state that STILL carries the
 * expected epoch but is missing nonce keys consumed after that snapshot. The
 * epoch is unchanged, so the marker check passes, and a replay from the lost
 * interval can be accepted.
 *
 * This module binds each accepted authorization to a monotonic sequence held
 * in an INDEPENDENT authoritative boundary (e.g. a fenced PostgreSQL row) on a
 * different failure domain than Redis. The sequence only ever advances. A
 * rollback reverts Redis's mirror of the sequence to an older value while the
 * external witness retains the higher value, so the disagreement is detectable:
 * the verifier fails closed whenever the external checkpoint is unavailable,
 * lower than Redis expects, inconsistent with Redis's epoch, or cannot be
 * advanced atomically (fencing conflict).
 *
 * ┌── STATE TRANSITION THAT ADVANCES THE CHECKPOINT ───────────────────────────┐
 * │ Exactly one: a successful authorization that is about to consume a nonce.  │
 * │ Order per accept: (1) read external checkpoint C, (2) read Redis mirror R, │
 * │ (3) fail closed on any disagreement, (4) advance external C via fenced CAS,│
 * │ (5) mirror the new sequence into Redis. A crash between 4 and 5 leaves the  │
 * │ external ahead of Redis on restart -> detected as rollback -> fail closed   │
 * │ (safe: refuse, never double-accept).                                        │
 * └────────────────────────────────────────────────────────────────────────────┘
 *
 * RPO: any nonzero RPO (acknowledged writes that can be lost on failover) means
 * replay uncertainty for that interval and MUST be covered by quarantine for at
 * least the full nonce acceptance horizon — see redis-continuity.ts.
 *
 * SCOPE / RESIDUAL: this is the *mechanism*. Per issue #15 it is a production
 * topology/durability control and is NOT closed by unit tests of an in-memory
 * fake. Closing #15 requires the adversarial drill on real Redis + PostgreSQL
 * (snapshot -> accept -> restore-older -> prove replay denial; primary/replica
 * failover with lost acked writes; checkpoint outage/stale/split-brain; verifier
 * restart survival) with recorded versions, persistence settings, and RPO/RTO.
 * Until then, describe the guard as detecting missing/changed epoch + bounded
 * quarantine only — do not claim protection against every rollback.
 */

export class RollbackDetectedError extends Error {
  readonly code = 'continuity_rollback_detected';
  constructor(readonly redisSequence: number, readonly witnessSequence: number) {
    super(
      `Same-epoch rollback detected: Redis sequence ${redisSequence} is behind ` +
      `the independent witness ${witnessSequence} — Redis was restored to an ` +
      `older state; failing closed.`,
    );
    this.name = 'RollbackDetectedError';
  }
}

export class CheckpointUnavailableError extends Error {
  readonly code = 'continuity_checkpoint_unavailable';
  constructor(cause?: unknown) {
    super('Independent continuity checkpoint is unavailable — failing closed', { cause });
    this.name = 'CheckpointUnavailableError';
  }
}

export class CheckpointInconsistentError extends Error {
  readonly code = 'continuity_checkpoint_inconsistent';
  constructor(readonly redisEpoch: string, readonly witnessEpoch: string) {
    super(
      `Redis epoch ${redisEpoch!} disagrees with the witness epoch ${witnessEpoch!} — ` +
      `failing closed`,
    );
    this.name = 'CheckpointInconsistentError';
  }
}

export class CheckpointConflictError extends Error {
  readonly code = 'continuity_checkpoint_conflict';
  constructor() {
    super('Checkpoint advanced concurrently (fencing conflict) — failing closed');
    this.name = 'CheckpointConflictError';
  }
}

/** Snapshot of the authoritative checkpoint for a namespace. */
export interface CheckpointState {
  epoch: string;
  sequence: number;
}

/**
 * Independent, authoritative, monotonic checkpoint. Implemented against a
 * fenced PostgreSQL row (or equivalent external witness) on a DIFFERENT failure
 * domain than Redis. A local file on Redis's own host does NOT satisfy this.
 */
export interface MonotonicCheckpoint {
  /**
   * Current {epoch, sequence}, or null if none exists yet. MUST throw (not
   * return a stale/guessed value) if the store cannot be reached — callers
   * fail closed on throw.
   */
  read(namespace: string): Promise<CheckpointState | null>;
  /**
   * Atomically set the checkpoint for `namespace` to `{epoch, sequence: next}`
   * ONLY IF its current state equals `expected` (compare-and-set / fencing).
   * Returns the new state on success; throws CheckpointConflictError if the
   * current state no longer equals `expected` (a concurrent writer or a
   * rollback moved it). Must be a single atomic transaction.
   */
  compareAndAdvance(
    namespace: string,
    expected: CheckpointState | null,
    next: CheckpointState,
  ): Promise<CheckpointState>;
}

/** Redis's mirror of the sequence for the current epoch, read by the caller. */
export interface RedisSequenceView {
  epoch: string;
  sequence: number;
}

export interface RollbackCheckpointOptions {
  namespace: string;
  /** Injected epoch factory for the very first checkpoint (unique per boot). */
  now?: () => number;
}

export class RollbackCheckpointGuard {
  constructor(
    private readonly witness: MonotonicCheckpoint,
    private readonly options: RollbackCheckpointOptions,
  ) {
    if (!options.namespace) throw new RangeError('namespace is required');
  }

  /**
   * Gate to run immediately before consuming a nonce. Compares Redis's mirror
   * against the independent witness and advances the witness for this accept.
   * Throws (fail closed) on any disagreement; on success returns the new
   * sequence the caller must mirror back into Redis.
   *
   * @param redis Redis's current view of {epoch, sequence}. When Redis has just
   *   claimed a fresh epoch (sequence 0) this bootstraps the witness.
   */
  async verifyAndAdvance(redis: RedisSequenceView): Promise<number> {
    const ns = this.options.namespace;
    let current: CheckpointState | null;
    try {
      current = await this.witness.read(ns);
    } catch (err) {
      throw new CheckpointUnavailableError(err);
    }

    if (current === null) {
      // First use for this witness: adopt Redis's epoch at its current
      // sequence, then advance by one for the accept in progress.
      return this.advance(ns, null, redis.epoch, redis.sequence);
    }

    if (current.epoch !== redis.epoch) {
      // Redis and the witness disagree on epoch. If Redis moved to a brand-new
      // epoch (fresh marker) the continuity guard handles that via quarantine;
      // here we refuse to advance an inconsistent pair.
      throw new CheckpointInconsistentError(redis.epoch, current.epoch);
    }

    if (redis.sequence < current.sequence) {
      // Redis's mirror is BEHIND the authoritative witness for the same epoch:
      // Redis was rolled back to an older snapshot. This is the #15 condition.
      throw new RollbackDetectedError(redis.sequence, current.sequence);
    }

    // Redis is at or ahead of the witness for this epoch. Advance the witness
    // by one (fenced) for this accept.
    return this.advance(ns, current, redis.epoch, current.sequence);
  }

  private async advance(
    ns: string,
    expected: CheckpointState | null,
    epoch: string,
    fromSequence: number,
  ): Promise<number> {
    const next: CheckpointState = { epoch, sequence: fromSequence + 1 };
    try {
      const result = await this.witness.compareAndAdvance(ns, expected, next);
      return result.sequence;
    } catch (err) {
      if (err instanceof CheckpointConflictError) throw err;
      throw new CheckpointUnavailableError(err);
    }
  }
}
