# Atomic Pair Registry Boundary

`AtomicPairStore` is the production authority capability used by `PairRegistry`.
It prevents lifecycle operations from being assembled from detached `get()` and
`set()` calls.

The capability provides:

- single-consumer pending approval with approval-time capacity enforcement;
- row-locked pair mutation that preserves unrelated concurrent fields;
- atomic old-pair disable plus replacement creation during rotation;
- atomic successful-use claims, including `maxRequests` enforcement; and
- condition-checked persisted expiry/lock transitions that re-evaluate fresh
  authority state, plus atomic unlock and revocation transitions.

`PgTransactionalPairStore` performs these operations in SERIALIZABLE
transactions and appends the corresponding durable outbox record in the same
transaction. Approval and rotation use compound mutations, so a receiver cannot
commit only half of either authority transition.

The final successful-use claim rechecks the current `expiresAt` and usage cap
under the same authority lock. It also binds the authorization-relevant policy
captured by verification: status, scope, mode, secret/key identity, expiry,
usage cap, pair kind, and canary class. Concurrent expiry or cap exhaustion
returns its durable terminal reason; any other policy mismatch returns a typed
state-change denial without incrementing usage. The request is never authorized
from a stale verification snapshot.

Construct `PairRegistry` with `requireAtomic=true` for production. The legacy
fallback remains for bounded single-writer adapters and is not a concurrency
guarantee.

## Bounded Claims

This mechanism does not close issue #16. Multi-node failover, Redis continuity,
snapshot/tail resynchronization, and measured RPO/RTO still require the real
two-node drill. The in-process IP failure tracker also remains node-local; pair
authority persistence is atomic, but cross-node IP anomaly aggregation is a
separate concern.
