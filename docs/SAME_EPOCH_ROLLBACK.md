# Same-epoch rollback detection + reservation (#15)

## What ships in code (this PR) — a narrowed primitive
`RollbackCheckpointGuard` (`packages/server/src/rollback-checkpoint.ts`) is a
**pre-authorization detection + reservation primitive** against an independent
authoritative monotonic witness (a fenced PostgreSQL row on a different failure
domain than Redis). It is **not** atomically coupled to nonce consumption.

- **`check(redis)`** — pure, side-effect-free verdict:
  `ok` | `rollback` | `redis-ahead` | `epoch-mismatch` | `witness-missing`.
- **`reserve(redis)`** — verify exact steady-state agreement, then fenced-advance
  the witness by one; returns the reserved sequence. Fails closed on any non-`ok`
  verdict.
- **`provision(genesisEpoch)`** — genesis creation gated by an injected
  `ProvisioningAuthorizer` bound in the constructor (a non-empty string is **not**
  authorization; the deployment binds real authentication/policy). Denied →
  `NotAuthorizedError`; authorizer unavailable or witness outage →
  `CheckpointUnavailableError` (fail closed); an existing row is refused.
  It creates ONLY the genesis row — it is **not** an epoch transition.

**Epoch transitions are NOT implemented** by this primitive and remain #15
scope: an epoch that differs from the witness is reported as `epoch-mismatch`
(fail closed). A governed, fenced, independently-approved epoch rotation is
future work required to close #15.

## Steady-state invariant (exact equality)
For the current epoch, Redis's mirrored sequence MUST **equal** the witness.
- `redis < witness` → `rollback` (Redis restored to an older snapshot).
- `redis > witness` → `redis-ahead` (the witness lost acknowledged writes, or
  Redis has un-witnessed writes) — **also** an anomaly.
- Both fail closed. Changing epoch is a **separate governed transition**
  (`provision`), never silent acceptance.

## No silent re-anchor
A missing witness row during `check`/`reserve` is `witness-missing` → fail
closed. The genesis row is created **only** by an explicit authorized
`provision(...)`. A deleted trust row plus a Redis rollback therefore cannot
bypass the anchor (regression-tested).

## Reservation semantics (honest boundary)
`reserve` advances the witness first; the caller mirrors the reserved sequence
into Redis afterward. A crash/duplicate/Redis-failure between reserve and commit
leaves the witness AHEAD of Redis, which `check` reports as `rollback` on the
next call — fail closed, never a double-accept. **There is no claim that one
reservation equals one consumed nonce.** An atomic reserve→consume→commit→
reconcile protocol is out of scope and part of closing #15.

## Hardening
Bounded namespace/epoch grammar; non-negative safe-integer sequences; sequence
exhaustion forces a governed epoch rotation; the CAS-returned state is validated
**exactly** (a store that returns a different state fails closed).

## What this does NOT do — #15 stays OPEN
Per issue #15 this is a production topology/durability control and unit tests of
an in-memory fake **cannot** close it. Closing requires a concrete
`MonotonicCheckpoint` on a fenced PostgreSQL row and a real Redis+PostgreSQL
adversarial drill (snapshot→accept→restore-older→prove denial; failover with
lost acked writes; witness outage/stale/split-brain; verifier-restart survival;
Redis hash-tag atomicity) with recorded versions/topology/RPO/RTO. No
release-claim expansion.

## Tests (13)
missing-witness fail-closed (check+reserve); authorized provisioning + empty-auth
refusal + re-provision refusal; exact-equality reserve advance; redis-behind
rollback; **redis-ahead anomaly (redis=10 witness=4)**; epoch mismatch; witness
outage; fencing conflict; **malformed-CAS**; sequence exhaustion; invalid
ids/sequences; **deletion regression**; reservation-before-commit crash detected
as rollback.
