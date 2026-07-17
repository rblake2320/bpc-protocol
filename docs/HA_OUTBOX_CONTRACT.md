# HA durable-replication outbox contract v1

**Shared, identical in `bpc-protocol` and `tsk-protocol`.** Owning issues:
bpc#16 (pair), tsk#10 (tumbler). Composed by enterprise#28 (Parent #21).

**Step 1 of 4** (contract → bpc#16 ∥ tsk#10 → ent#28): interfaces + schema +
canonical digest + shared vectors + I1–I9 only. **No runtime, no durability/HA
claims. Issues stay OPEN** — closed only by a real two-node PostgreSQL(+Redis)
adversarial drill.

## Normative, language-neutral digest
- **Framing (length-prefixed, no separator collision):**
  `sha256( Σ u32be(utf8ByteLen(field)) ‖ utf8(field) )` over fields in fixed
  order: `domain, contractVersion, streamId, sourceEpoch, decimal(sequence),
  JCS(mutation)`.
- **Canonicalization:** RFC 8785 (JCS) restricted to RFC 7493 (I-JSON).
  Accept only null / boolean / **safe-integer** number / string / dense array /
  plain object; keys sorted by UTF-16 code unit. **Reject** undefined,
  non-finite/non-integer numbers, bigint, function, symbol, Date/Map/Set/typed
  arrays/class instances, sparse arrays, and `__proto__` keys. Bounded depth
  (64) and node count (10k).
- The shared **vectors** (`ha-outbox-contract.vectors.json`) are the
  language-neutral ground truth: positive digests, tamper deltas, adversarial
  rejects, framing non-collision, key-order invariance. Both repos reproduce
  identical digests.

## Contract points (review-hardened a–i)
| # | Requirement |
|---|-------------|
| a | `contractVersion` **literal `'1'`** (others rejected) + bounded versioned `streamId`/`sourceEpoch` (`ID_PATTERN`). |
| b | `opDigest` over the length-prefixed canonical bytes above, with shared positive/tamper/reject vectors. |
| c | Idempotency key `(streamId, sourceEpoch, sequence)`; duplicate `duplicate-ok` only if digest identical, else `reject-fork`. |
| d | `DurableOutbox.appendInTx` enlists the caller's opaque, backend-bound `DurableTx`. |
| e | Receiver is **one atomic op** `verifyAndApplyInTx` that owns lock + idempotency + verify + mutation + checkpoint (no separate `classify` — its TOCTOU allowed double-apply / HOTP double-consume). |
| f | Persisted `mutation` is a typed `SanitizedMutation` from a validated protocol `MutationSanitizer` (secret-stripped before digest/enqueue), not prose. |
| g | Publisher **only drains** (idempotent retries, ACKs, never sheds). Admission/backpressure is **inside the tx** at `appendInTx`: at the bound it throws `OutboxBackpressureError`, aborting the authoritative mutation. |
| h | `PromotionFence` token is a monotonic **bigint persisted and stale-rejected by the authoritative resource** (`StaleFenceError`), not merely carried; a process-local predicate is non-conformant. |
| i | `DurableOutbox.appendInTx` **allocates the sequence inside the tx**, binding allocation + mutation + outbox row atomically. |

## Genesis / epoch / resync (8)
Genesis = sequence 0 of a source epoch; first accepted mutation is sequence 1.
A new `sourceEpoch` begins **only** after detected loss/resync; its sequence
restarts at 0. A gap (received > checkpoint+1) is **never** filled by
assumption — it forces snapshot + tail resync under a new epoch (`EpochBoundary`).

## Failure invariants (I1–I9)
I1 no acknowledged mutation lost · I2 no double apply (HOTP never double-consumed
in tsk) · I3 loss leaves a detectable monotonic gap · I4 crash at any boundary →
safe/recoverable · I5 no stale/gapped/tampered/rolled-back/metadata-only promote;
needs convergence + external fence · I6 same-epoch rollback detected (bpc#15) →
fail closed · I7 backpressure fails/quarantines, never sheds · I8 metadata-only
replicas by default; promotion needs authorized unseal · I9 any nonzero RPO
quarantined for the full acceptance horizon, documented.

## Per-protocol (impl PRs)
- **bpc#16**: replaces process-local `ReplicatingPairStore` shed-oldest queue +
  process-local PromotionController (not the fence); needs the external fence.
- **tsk#10**: HOTP counter never double-consumed + signed/hash-linked stream head
  committed in the same tx; the existing Redis lease implements `PromotionFence`.

## Boundary
Unit tests of these interfaces/vectors do **not** establish crash-durable
independent-state HA. #16/#10/#28 stay open until the real two-node drill (crash
at every boundary, failover with lost acks, split-brain, restore, restart
survival) with recorded versions/topology/RPO/RTO passes. No release-claim
expansion.
