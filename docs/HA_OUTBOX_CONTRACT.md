# HA durable-replication outbox contract v1

**Shared, identical in `bpc-protocol` and `tsk-protocol`.** Owning issues:
bpc#16 (pair), tsk#10 (tumbler). Composed by enterprise#28 (Parent #21).

This is **step 1 of 4**: interfaces + schema + canonical-digest + shared vectors
+ invariants only. **No runtime, no durability/HA claims.** Implementations land
in the per-repo PRs and are only validated by a real two-node PostgreSQL(+Redis)
adversarial drill. Merge order: **contract (this) → bpc#16 ∥ tsk#10 → ent#28.**

## Precision requirements (Codex-approved a–h)
- **(a)** Every record carries `contractVersion` and a versioned `streamId`
  (`bpc:pair:<ns>/v1`, `tsk:tumbler:<ns>/v1`). `HA_OUTBOX_CONTRACT_VERSION` bumps
  only on a breaking schema/digest change.
- **(b)** `opDigest` is over **explicitly canonical bytes**:
  `sha256hex(domain ␟ version ␟ streamId ␟ sourceEpoch ␟ sequence ␟ canonicalJSON(mutation))`,
  `canonicalJSON` = recursively key-sorted, non-finite rejected. Shared
  positive + tamper **vectors** in `ha-outbox-contract.vectors.json`; both repos
  reproduce identical digests (cross-repo agreement test).
- **(c)** Idempotency key = `(streamId, sourceEpoch, sequence)`. Duplicate is
  `duplicate-ok` **only** when `opDigest` is byte-identical; same key + different
  digest = `reject-fork`.
- **(d)** `DurableOutbox.enqueueInTx(tx, record)` MUST enlist in the caller's
  already-open durable transaction — mutation + epoch/sequence + digest + outbox
  row commit or roll back together. Nested/best-effort/separate tx is
  non-conformant.
- **(e)** `ReceiverCheckpoint.applyInTx` applies mutation **and** advances the
  durable `{epoch, sequence, digest[, streamHead]}` checkpoint in one atomic tx.
- **(f)** The persisted `mutation` is **secret-stripped before digest and
  enqueue**; replicas are metadata-only by default.
- **(g)** `OutboxPublisher.backpressure` is normative and fail-closed:
  `fail-authoritative-mutation` or `quarantine`. **Shedding any pending row is
  prohibited** (kills the current shed-oldest behavior). Never silently drops.
- **(h)** `PromotionFence` is an **external** distributed fence interface; a
  process-local controller/predicate is not a conformant substitute. Promotion
  also requires durable source==receiver convergence.

## Failure invariants (I1–I9)
| # | Invariant |
|---|-----------|
| I1 | No acknowledged primary mutation disappears. |
| I2 | No operation applies twice (idempotent by key; HOTP counter never double-consumed in tsk). |
| I3 | Any lost mutation leaves a detectable monotonic-sequence gap; never fill by assumption. |
| I4 | Crash at any boundary → safe recoverable state, never silent loss/double. |
| I5 | No stale/gapped/tampered/rolled-back/metadata-only replica promotes; needs convergence + external fence. |
| I6 | Same-epoch rollback detected (reuse bpc#15 `MonotonicCheckpoint`) → fail closed. |
| I7 | Backpressure fails the mutation or quarantines; never sheds. |
| I8 | Metadata-only replicas by default; secrets sealed; promotion needs authorized unseal. |
| I9 | Any nonzero RPO quarantined for the full acceptance horizon and documented; no zero-loss claim without the drill. |

## Per-protocol notes
- **bpc#16**: replaces process-local `ReplicatingPairStore` queue (shed-oldest) +
  process-local PromotionController (not the fence). Needs an external fence impl.
- **tsk#10**: adds HOTP-counter-no-double-consume + signed/hash-linked stream
  head in the same tx; the existing Redis lease is the `PromotionFence` impl.

## Boundary
Unit tests of these interfaces/vectors do **not** establish crash-durable
independent-state HA. #16/#10/#28 stay open until the real two-node drill (crash
at every boundary, failover with lost acks, split-brain, restore, restart
survival) with recorded versions/topology/RPO/RTO passes. No release-claim
expansion.
