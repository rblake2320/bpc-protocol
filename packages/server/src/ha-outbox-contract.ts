/**
 * HA durable-replication outbox CONTRACT v1 (bpc#16 / tsk#10 / ent#28).
 *
 * SHARED, IDENTICAL in bpc-protocol and tsk-protocol. This file is the contract
 * ONLY: type-only interfaces, the record schema, and the normative canonical
 * digest used to produce cross-repo test vectors. It contains NO runtime
 * replication behavior and makes NO durability/HA claims — those land in the
 * per-repo implementation PRs (#16, #10) and are validated by a real two-node
 * PostgreSQL(+Redis) drill (#28). Do not describe anything here as crash-durable.
 *
 * The eight precision requirements (a–h) are pinned below at their definitions.
 */
import { createHash } from 'node:crypto';

/** (a) Bump only on a breaking change to schema or digest algorithm. */
export const HA_OUTBOX_CONTRACT_VERSION = '1' as const;

/** Domain-separation tag mixed into every digest so vectors can't collide
 *  with other hashing in the codebase. */
export const HA_OUTBOX_DIGEST_DOMAIN = 'selfconnect/ha-outbox/v1' as const;

/**
 * (a) Every record carries a versioned stream_id and contract_version.
 * (f) `mutation` is the SECRET-STRIPPED payload — secrets are removed BEFORE the
 *     digest is computed and before the row is enqueued; replicas are metadata-
 *     only by default.
 */
export interface OutboxRecordHeader {
  /** contract_version — MUST equal HA_OUTBOX_CONTRACT_VERSION for v1 rows. */
  contractVersion: string;
  /** (a) Versioned stream identity, e.g. 'bpc:pair:<ns>/v1' or 'tsk:tumbler:<ns>/v1'. */
  streamId: string;
  /** Monotonic source epoch (rotates on detected loss / new source). */
  sourceEpoch: string;
  /** Monotonic per-(streamId,sourceEpoch) sequence. Gaps are detectable. */
  sequence: number;
  /** (b) Digest over the canonical bytes of the secret-stripped record. */
  opDigest: string;
}

/** The full record: header + the secret-stripped mutation payload. */
export interface OutboxRecord<M = unknown> extends OutboxRecordHeader {
  /** (f) Secret-stripped mutation. MUST NOT contain key/secret material. */
  mutation: M;
}

/**
 * (c) Idempotency key = (streamId, sourceEpoch, sequence). A duplicate delivery
 *     is accepted ONLY when its opDigest is byte-identical; a same-key record
 *     with a different digest is a fork/tamper and MUST be rejected.
 */
export interface IdempotencyKey {
  streamId: string;
  sourceEpoch: string;
  sequence: number;
}

export function idempotencyKeyOf(h: OutboxRecordHeader): IdempotencyKey {
  return { streamId: h.streamId, sourceEpoch: h.sourceEpoch, sequence: h.sequence };
}

/**
 * (b) NORMATIVE canonical digest. Deterministic across repos:
 *   digest = sha256hex( domain \x1f version \x1f streamId \x1f sourceEpoch
 *                        \x1f sequence \x1f canonicalJSON(mutation) )
 * canonicalJSON sorts object keys recursively and rejects non-finite numbers.
 * The secret-stripped mutation MUST be passed (never the raw payload).
 */
export function canonicalOpDigest(input: {
  streamId: string;
  sourceEpoch: string;
  sequence: number;
  mutation: unknown;
}): string {
  if (!Number.isSafeInteger(input.sequence) || input.sequence < 0) {
    throw new RangeError('sequence must be a non-negative safe integer');
  }
  const US = '\x1f'; // unit separator — unambiguous field boundary
  const canonical =
    HA_OUTBOX_DIGEST_DOMAIN + US +
    HA_OUTBOX_CONTRACT_VERSION + US +
    input.streamId + US +
    input.sourceEpoch + US +
    String(input.sequence) + US +
    canonicalJSON(input.mutation);
  return createHash('sha256').update(canonical, 'utf8').digest('hex');
}

/** Deterministic JSON: recursively sorted object keys, rejects NaN/Infinity. */
export function canonicalJSON(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(value as Record<string, unknown>).sort()) {
      out[k] = sortKeys((value as Record<string, unknown>)[k]);
    }
    return out;
  }
  if (typeof value === 'number' && !Number.isFinite(value)) {
    throw new RangeError('non-finite number is not canonicalizable');
  }
  return value;
}

// ── Interfaces (type-only; per-repo impls provide behavior) ──────────────────

/** Abstract single durable transaction the caller owns. Implementations map
 *  this to a real DB transaction handle (e.g. a PostgreSQL tx). */
export interface DurableTx {
  readonly id: string;
}

/**
 * (d) enqueueInTx MUST enlist in the caller's already-open durable transaction —
 *     the mutation, source epoch/sequence, digest, and outbox row commit or roll
 *     back TOGETHER. A nested/best-effort/separate transaction is non-conformant.
 */
export interface DurableOutbox<M = unknown> {
  enqueueInTx(tx: DurableTx, record: OutboxRecord<M>): Promise<void>;
}

/**
 * (g) Publisher backpressure is NORMATIVE and fail-closed: when it cannot make
 *     progress it MUST either fail the authoritative mutation or enter the
 *     declared quarantine state. Shedding the oldest (or any) pending row is
 *     PROHIBITED. It drains committed rows, retries idempotently, records ACKs,
 *     and never silently drops.
 */
export type PublisherBackpressure = 'fail-authoritative-mutation' | 'quarantine';

export interface OutboxPublisher {
  drainOnce(): Promise<{ published: number; acked: number }>;
  /** The declared, non-shedding backpressure policy this publisher enforces. */
  readonly backpressure: PublisherBackpressure;
}

/** Receiver decision for an incoming record. */
export type ReceiverDecision =
  | 'apply'          // fresh, in-order → apply + checkpoint atomically
  | 'duplicate-ok'   // (c) same key AND same digest → no-op, idempotent
  | 'reject-gap'     // sequence ahead of checkpoint+1 → gap, resync required
  | 'reject-fork'    // (c) same key, DIFFERENT digest → fork/tamper
  | 'reject-stale'   // sequence <= checkpoint → replay/rollback
  | 'reject-epoch';  // unknown/backward source epoch

/**
 * (e) Receiver apply + checkpoint advance MUST be one atomic transaction:
 *     the mutation and the durable {epoch, sequence, digest[, streamHead]}
 *     checkpoint commit together or not at all.
 */
export interface ReceiverCheckpoint<M = unknown> {
  classify(record: OutboxRecord<M>): Promise<ReceiverDecision>;
  applyInTx(tx: DurableTx, record: OutboxRecord<M>): Promise<void>;
}

/**
 * (h) Promotion fence is EXTERNAL and distributed. A process-local controller/
 *     predicate is NOT a conformant substitute. Promotion additionally requires
 *     durable source==receiver convergence (checked by the caller) AND the fence
 *     token being held.
 */
export interface PromotionFence {
  /** Acquire the external fence; returns a monotically increasing token or null. */
  acquire(streamId: string): Promise<{ token: number } | null>;
  /** True iff `token` is still the current fence holder. */
  isHeld(streamId: string, token: number): Promise<boolean>;
}
