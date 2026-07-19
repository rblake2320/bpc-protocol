# BPC HA final acceptance

`bpc-ha-acceptance-drill.mts` is the frozen issue #16 acceptance command. It
uses three PostgreSQL cluster identities (A, B, and an external control
authority), a three-member durable Redis fencing quorum, the
authenticated durable-outbox transport, and separate child processes.

The public HA construction path is `createHaPairAuthority`; it requires an
unforgeable, database-bound `PgSourceLeaseFence` capability. The ordinary
`PgTransactionalPairStore` remains the explicitly single-node API. The HA
fence verifies a
guard-signed lease head against the latest append-only history row and locks
the current lease inside the same PostgreSQL transaction as the pair mutation
and outbox append. The lease
expires according to the source database clock. Losing connectivity to Redis
therefore cannot let the former source renew itself or bypass expiry.

Promotion writes a signed PREPARING record to the control database before the
Redis effect. It freezes A with a signed revocation plus control-clock lease
expiry, requires an exact signed majority Redis claim, and advances an external
epoch witness with a signed FENCED record. A signed snapshot exports and
re-digests every retained source record from genesis through C into a fresh B;
the authenticated transport then replays C+1..N. Promotion verifies B's exact
applied-history and pair/pending state before it records the receipt. Redis
admits only a strictly higher epoch. B must also hold a valid
guard-signed source lease before its first authoritative mutation commits.

## Executable evidence

The acceptance command proves:

- A, B, and control have distinct PostgreSQL `system_identifier` values.
- A publisher process is killed after B commits but before A records the ACK;
  a fresh process reclaims the durable row and converges without double apply.
- A live TCP partition prevents old A from reaching Redis while A can still
  reach its PostgreSQL database; its expired in-transaction lease rejects the
  write and rolls back the pair/outbox mutation.
- A signed snapshot is imported into a reset/empty B authority, malicious
  snapshot tampering is rejected, then the tail imports every sequence through
  frozen `N` and B's exact applied history/state match A before promotion.
- The three-member Redis quorum stays readable with one member unavailable,
  fails closed with two unavailable, rejects a competing equal-epoch claim,
  and rejects a two-member rollback below the external epoch witness. After an
  exact signed quorum restore, B resumes without resetting its epoch. B
  originates `N+1` under the
  new epoch, and old A remains denied.
- Each recoverable fault prints backlog at fault, data-loss RPO after
  convergence, and RTO from fault/cutover trigger to convergence and writable
  promoted authority.
- A deterministic transaction barrier starts mutation/outbox DML while A is
  valid, revokes A before callback return, and proves the pre-commit check rolls
  the whole transaction back. This is distinct from rejecting at construction.

The snapshot key (`source-v1`) and control/lease key (`guard-v1`) are distinct
Ed25519 identities in the executable drill. Deployments must keep those keys in
separate custody and enforce a runtime database role without DDL or direct
control-table mutation privileges.

Run with:

```text
BPC_TEST_POSTGRES_URL=<node-a> \
BPC_TEST_POSTGRES_B_URL=<node-b> \
BPC_TEST_POSTGRES_CONTROL_URL=<control> \
BPC_TEST_REDIS_URLS=<redis-1>,<redis-2>,<redis-3> \
npm run test:ha:acceptance
```

The command throws when any required authority is absent; CI cannot silently
skip it. It establishes the tested topology and fault matrix, not an ATO,
FedRAMP authorization, DoD Impact Level authorization, or a universal uptime
guarantee for a different deployment topology.
