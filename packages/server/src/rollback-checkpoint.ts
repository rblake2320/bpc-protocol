/**
 * Same-epoch rollback DETECTION + fenced RESERVATION primitive — #15.
 *
 * SCOPE (narrowed per review, HIGH3): this is a pre-authorization detection +
 * reservation primitive, NOT an atomic coupling to nonce consumption. It does
 * two things against an INDEPENDENT authoritative monotonic witness (a fenced
 * PostgreSQL row on a different failure domain than Redis):
 *
 *   - `check(redis)`  — pure, side-effect-free rollback detection.
 *   - `reserve(redis)`— verify then fenced-advance the witness by one, returning
 *                       the reserved sequence the caller then mirrors into Redis.
 *
 * `reserve` is a RESERVATION: the witness advances first, the caller commits to
 * Redis after. A crash/duplicate/Redis-failure between reserve and commit leaves
 * the witness AHEAD of Redis, which `check` reports as `rollback` (redis behind)
 * and callers MUST treat as fail-closed. There is deliberately NO claim that one
 * reservation equals one consumed nonce; wiring an atomic reserve→consume→commit
 * →reconcile protocol is out of scope and part of closing #15.
 *
 * STEADY STATE (HIGH1): Redis's mirrored sequence MUST EQUAL the witness for the
 * current epoch. `redis < witness` = same-epoch rollback (restored older
 * snapshot). `redis > witness` = the witness lost acknowledged writes (or Redis
 * has un-witnessed writes) — ALSO an anomaly; both fail closed. An epoch CHANGE
 * (rotation to a new sourceEpoch after a governed resync) is NOT implemented by
 * this primitive and remains #15 scope; here an epoch that differs from the
 * witness is simply `epoch-mismatch` (fail closed).
 *
 * PROVISIONING (HIGH2): the genesis witness row is created ONLY by an explicit
 * `provision(...)` call whose authorization is decided by an injected
 * `ProvisioningAuthorizer` bound in the constructor (a non-empty string is NOT
 * authorization). `provision` creates ONLY the genesis row and refuses if one
 * already exists — it is not an epoch-transition. A missing witness row during
 * `check`/`reserve` is fail-closed (`WitnessMissingError`) — there is NO silent
 * re-anchor to whatever Redis currently claims (that would let a deleted trust
 * row + a Redis rollback bypass the anchor).
 *
 * ISSUE #15 STAYS OPEN — a production topology control; unit tests of an
 * in-memory fake cannot close it. See docs/SAME_EPOCH_ROLLBACK.md. No runtime
 * durability/HA claim is made here.
 */

// ── Errors (all fail closed) ─────────────────────────────────────────────────
export class RollbackDetectedError extends Error {
  readonly code = 'continuity_rollback_detected';
  constructor(readonly redisSequence: number, readonly witnessSequence: number) {
    super(`Same-epoch rollback: Redis sequence ${redisSequence} is behind the witness ${witnessSequence} — failing closed.`);
    this.name = 'RollbackDetectedError';
  }
}
export class RedisAheadError extends Error {
  readonly code = 'continuity_redis_ahead';
  constructor(readonly redisSequence: number, readonly witnessSequence: number) {
    super(`Redis sequence ${redisSequence} is AHEAD of the authoritative witness ${witnessSequence} — the witness lost writes or Redis has un-witnessed writes; failing closed.`);
    this.name = 'RedisAheadError';
  }
}
export class WitnessMissingError extends Error {
  readonly code = 'continuity_witness_missing';
  constructor(readonly namespace: string) {
    super(`No authoritative witness row for '${namespace}' — provision explicitly; failing closed (no silent re-anchor).`);
    this.name = 'WitnessMissingError';
  }
}
export class CheckpointUnavailableError extends Error {
  readonly code = 'continuity_checkpoint_unavailable';
  constructor(cause?: unknown) { super('Independent continuity checkpoint is unavailable — failing closed', { cause }); this.name = 'CheckpointUnavailableError'; }
}
export class CheckpointInconsistentError extends Error {
  readonly code = 'continuity_checkpoint_epoch_mismatch';
  constructor(readonly redisEpoch: string, readonly witnessEpoch: string) {
    super(`Redis epoch '${redisEpoch}' != witness epoch '${witnessEpoch}' — failing closed (epoch change is a governed transition).`);
    this.name = 'CheckpointInconsistentError';
  }
}
export class CheckpointConflictError extends Error {
  readonly code = 'continuity_checkpoint_conflict';
  constructor() { super('Witness advanced concurrently (fencing conflict) — failing closed'); this.name = 'CheckpointConflictError'; }
}
export class MalformedCasError extends Error {
  readonly code = 'continuity_malformed_cas';
  constructor(readonly expected: CheckpointState, readonly got: unknown) {
    super('Witness compareAndAdvance returned a state other than the requested next — failing closed');
    this.name = 'MalformedCasError';
  }
}
export class SequenceExhaustedError extends Error {
  readonly code = 'continuity_sequence_exhausted';
  constructor(readonly sequence: number) { super(`Sequence ${sequence} is at the safe-integer ceiling — rotate the epoch (governed) before continuing.`); this.name = 'SequenceExhaustedError'; }
}
export class NotAuthorizedError extends Error {
  readonly code = 'continuity_provision_unauthorized';
  constructor() { super('Explicit authorization is required to provision a genesis witness row'); this.name = 'NotAuthorizedError'; }
}
export class ContinuityValidationError extends Error {
  readonly code = 'continuity_validation';
  constructor(message: string) { super(message); this.name = 'ContinuityValidationError'; }
}

// ── Types ────────────────────────────────────────────────────────────────────
export interface CheckpointState {
  epoch: string;
  sequence: number;
}
export interface RedisSequenceView {
  epoch: string;
  sequence: number;
}
export type RollbackVerdict = 'ok' | 'rollback' | 'redis-ahead' | 'epoch-mismatch' | 'witness-missing';

/** (MED4) bounded identifier grammar for namespace/epoch. */
const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}$/;
const MAX_SEQUENCE = Number.MAX_SAFE_INTEGER - 1;

function assertId(v: string, label: string): void {
  if (typeof v !== 'string' || !ID_PATTERN.test(v)) throw new ContinuityValidationError(`${label} must match ${ID_PATTERN}`);
}
function assertSeq(n: number, label: string): void {
  if (!Number.isSafeInteger(n) || n < 0) throw new ContinuityValidationError(`${label} must be a non-negative safe integer`);
}
function assertState(s: unknown, label: string): asserts s is CheckpointState {
  if (!s || typeof s !== 'object') throw new ContinuityValidationError(`${label} must be a state object`);
  const st = s as CheckpointState;
  assertId(st.epoch, `${label}.epoch`);
  assertSeq(st.sequence, `${label}.sequence`);
}

/**
 * Independent, authoritative, monotonic witness. Real impl = a fenced
 * PostgreSQL row on a DIFFERENT failure domain than Redis. A local file on
 * Redis's host does NOT satisfy this.
 */
export interface MonotonicCheckpoint {
  /** Current state, or null if none exists. MUST throw (never guess) on outage. */
  read(namespace: string): Promise<CheckpointState | null>;
  /** Atomic CAS: set to `next` iff current == `expected`; else throw
   *  CheckpointConflictError. Returns the persisted new state. */
  compareAndAdvance(namespace: string, expected: CheckpointState | null, next: CheckpointState): Promise<CheckpointState>;
  /** Create the genesis row iff none exists; throw CheckpointConflictError if
   *  one already exists. Used only by explicit provisioning. */
  createGenesis(namespace: string, genesis: CheckpointState): Promise<CheckpointState>;
}

/**
 * Decides whether a genesis provisioning is authorized. The deployment binds
 * real authentication/policy here (governed boundary, signed capability, mTLS
 * peer identity, etc.) — the guard itself makes no authentication claim. MUST
 * throw if the decision cannot be made (authorizer unavailable) so the guard
 * fails closed rather than proceeding.
 */
export interface ProvisioningAuthorizer {
  authorizeProvision(namespace: string, genesisEpoch: string): Promise<boolean>;
}

export interface RollbackCheckpointOptions {
  namespace: string;
  /** Required. Authorization for genesis provisioning is delegated here. */
  authorizer: ProvisioningAuthorizer;
}

export class RollbackCheckpointGuard {
  private readonly ns: string;
  private readonly authorizer: ProvisioningAuthorizer;

  constructor(private readonly witness: MonotonicCheckpoint, options: RollbackCheckpointOptions) {
    assertId(options.namespace, 'namespace');
    if (!options.authorizer || typeof options.authorizer.authorizeProvision !== 'function') {
      throw new ContinuityValidationError('a ProvisioningAuthorizer is required');
    }
    this.ns = options.namespace;
    this.authorizer = options.authorizer;
  }

  /**
   * (HIGH2 / re-review A) Genesis provisioning gated by the injected
   * ProvisioningAuthorizer — NOT by a caller-supplied string. Denied → throws
   * NotAuthorizedError; authorizer unavailable OR witness outage → throws
   * CheckpointUnavailableError (fail closed). Creates ONLY the genesis row and
   * refuses if one already exists (this is not an epoch transition).
   */
  async provision(genesisEpoch: string): Promise<CheckpointState> {
    assertId(genesisEpoch, 'genesisEpoch');
    let allowed: boolean;
    try {
      allowed = await this.authorizer.authorizeProvision(this.ns, genesisEpoch);
    } catch (err) {
      throw new CheckpointUnavailableError(err);
    }
    if (!allowed) throw new NotAuthorizedError();
    try {
      return await this.witness.createGenesis(this.ns, { epoch: genesisEpoch, sequence: 0 });
    } catch (err) {
      if (err instanceof CheckpointConflictError) throw err;
      throw new CheckpointUnavailableError(err);
    }
  }

  /** (HIGH1) Pure detection, no side effects. Fails closed on outage. */
  async check(redis: RedisSequenceView): Promise<RollbackVerdict> {
    assertId(redis.epoch, 'redis.epoch');
    assertSeq(redis.sequence, 'redis.sequence');
    let current: CheckpointState | null;
    try {
      current = await this.witness.read(this.ns);
    } catch (err) {
      throw new CheckpointUnavailableError(err);
    }
    if (current === null) return 'witness-missing';
    assertState(current, 'witness');
    if (current.epoch !== redis.epoch) return 'epoch-mismatch';
    if (redis.sequence < current.sequence) return 'rollback';
    if (redis.sequence > current.sequence) return 'redis-ahead';
    return 'ok';
  }

  /**
   * Pre-auth RESERVATION: verify exact steady-state agreement then fenced-advance
   * the witness by one, returning the reserved sequence. Throws (fail closed) on
   * any non-'ok' verdict. NOT atomically coupled to nonce consumption — see the
   * module header.
   */
  async reserve(redis: RedisSequenceView): Promise<number> {
    const verdict = await this.check(redis);
    switch (verdict) {
      case 'witness-missing': throw new WitnessMissingError(this.ns);
      case 'epoch-mismatch': {
        const w = await this.witness.read(this.ns);
        throw new CheckpointInconsistentError(redis.epoch, w ? w.epoch : '(none)');
      }
      case 'rollback': {
        const w = (await this.witness.read(this.ns))!;
        throw new RollbackDetectedError(redis.sequence, w.sequence);
      }
      case 'redis-ahead': {
        const w = (await this.witness.read(this.ns))!;
        throw new RedisAheadError(redis.sequence, w.sequence);
      }
      case 'ok':
        break;
    }
    // verdict === 'ok': redis.sequence === witness.sequence exactly.
    if (redis.sequence >= MAX_SEQUENCE) throw new SequenceExhaustedError(redis.sequence);
    const expected: CheckpointState = { epoch: redis.epoch, sequence: redis.sequence };
    const next: CheckpointState = { epoch: redis.epoch, sequence: redis.sequence + 1 };
    let result: CheckpointState;
    try {
      result = await this.witness.compareAndAdvance(this.ns, expected, next);
    } catch (err) {
      if (err instanceof CheckpointConflictError) throw err;
      throw new CheckpointUnavailableError(err);
    }
    // (MED4) validate CAS-returned state EXACTLY.
    if (!result || result.epoch !== next.epoch || result.sequence !== next.sequence) {
      throw new MalformedCasError(next, result);
    }
    return result.sequence;
  }
}
