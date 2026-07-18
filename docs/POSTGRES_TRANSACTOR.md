# Production PostgreSQL Transaction Adapter

`NodePostgresTransactor` is the production `pg` pool adapter for the durable
outbox mechanism. It enforces `SERIALIZABLE`, installs and verifies a server-side
statement timeout, verifies `BEGIN` and `COMMIT` command tags, bounds the entire
transaction without requiring a caller signal, and destroys failed or timed-out
connections rather than returning them to the pool.

## Outcome contract

- An error before `COMMIT` is dispatched is a definite transaction failure.
- An explicit PostgreSQL `ROLLBACK` command tag after `COMMIT` is a definite
  abort. Missing, malformed, or any other unexpected command tag is ambiguous.
- `AmbiguousCommitError` means `COMMIT` was dispatched but its response was lost.
  Its `committed` property is `"unknown"`. Do not blindly retry. Reconcile using
  the mutation/outbox idempotency key and authoritative checkpoint first.
- `PostCommitReleaseError` means PostgreSQL confirmed the commit, but the client
  could not be returned to the pool. Its `committed` property is `true`.
- `ConnectionDisposalError` means the transaction failed and the connection also
  could not be disposed. Its `committed` property is `false`.

Serialization and deadlock retries are disabled by default because callbacks can
contain non-database side effects. Enable bounded retries only for callbacks that
are safe to replay.

## Deployment boundary

Configure the `pg.Pool` with TLS, bounded connection and socket timeouts, and
least-privilege runtime credentials. The runtime role must not have DDL rights;
schema provisioning and attestation use a separate startup/migration identity.
Use `onDisposalError` to feed connection-disposal faults to operational telemetry.

This adapter and the single-node PostgreSQL integration do not prove high
availability. Issue #16 remains open until the real two-node PostgreSQL and Redis
failover/split-brain drill records measured RPO and RTO.
