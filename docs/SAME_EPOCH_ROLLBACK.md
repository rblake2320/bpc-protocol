# Same-epoch rollback control (#15)

## What ships in code (this PR)
`RollbackCheckpointGuard` + the `MonotonicCheckpoint` interface
(`packages/server/src/rollback-checkpoint.ts`). The guard binds each accepted
authorization to a monotonic sequence held in an **independent authoritative
witness** (a fenced PostgreSQL row, or equivalent, on a different failure
domain than Redis) and **fails closed** when:

- the witness is unavailable (`CheckpointUnavailableError`);
- Redis's mirrored sequence is **behind** the witness for the same epoch — a
  same-epoch rollback (`RollbackDetectedError`);
- Redis and the witness disagree on epoch (`CheckpointInconsistentError`);
- the witness cannot be advanced atomically (`CheckpointConflictError`).

The transition that advances the checkpoint is defined precisely: **exactly one
advance per authorization that is about to consume a nonce**, ordered
read-witness → read-Redis → fail-closed-on-disagreement → fenced CAS advance →
mirror into Redis. A crash between the witness advance and the Redis mirror
leaves the witness ahead of Redis, which is detected as a rollback on restart —
safe (refuse), never a double-accept.

Unit tests (`tests/rollback-checkpoint.test.ts`, 8) prove each fail-closed
decision including rollback detection and witness-survives-restart.

## What this does NOT do — the issue stays OPEN
Per issue #15, this is a **production topology/durability control** and unit
tests of an in-memory fake **cannot close it**. Closing #15 requires a real
adversarial drill and recorded evidence:

1. Provide a concrete `MonotonicCheckpoint` backed by a fenced PostgreSQL row
   (single transaction CAS; a local file on Redis's host is explicitly **not**
   acceptable).
2. Drill on real Redis + PostgreSQL and record versions, persistence settings,
   topology, RPO/RTO, exact commands, source commit, and non-secret results:
   - accept → snapshot Redis → accept more → restore the older same-epoch
     snapshot → replay a post-snapshot nonce → **prove denial/quarantine**;
   - primary/replica failover with lost acknowledged writes;
   - witness outage, stale read, rollback, concurrent writers, clock skew,
     split brain;
   - restart all verifier processes and prove the witness survives;
   - prove no request is accepted while Redis and the witness disagree.
3. Preserve Redis cluster hash-tag atomicity for the epoch/quarantine/nonce
   operation.

## RPO
Any nonzero RPO (acknowledged writes lost on failover) means replay uncertainty
for that interval and requires quarantine for at least the full nonce
acceptance horizon (see `redis-continuity.ts`). This control detects rollback
**after** the witness has advanced past Redis; it does not by itself recover the
lost interval — that interval must be quarantined.

## Claim boundary (until #15 closes)
Describe the continuity guard as detecting live missing/changed epoch and
enforcing a bounded quarantine, plus a rollback-detection **mechanism** pending
production validation. Do **not** claim protection against every rollback or
acknowledged-write loss.
