/**
 * HA durable-replication outbox CONTRACT v1 (bpc#16 / tsk#10 / ent#28).
 *
 * SHARED, IDENTICAL in bpc-protocol and tsk-protocol. Contract ONLY: type-only
 * interfaces, the record schema, and the NORMATIVE, LANGUAGE-NEUTRAL canonical
 * digest used to produce cross-repo vectors. NO runtime replication behavior and
 * NO durability/HA claims — those land in the per-repo impl PRs (#16, #10) and
 * are validated by a real two-node PostgreSQL(+Redis) drill (#28). Issues stay
 * OPEN. Do not describe anything here as crash-durable.
 *
 * This revision addresses the contract review (a–i + precision):
 *  (1) length-prefixed digest framing (no separator collision) + bounded IDs
 *  (2) strict RFC 8785 (JCS) / RFC 7493 (I-JSON) canonicalization, reject
 *      non-JSON values; the vectors are the language-neutral ground truth
 *  (3) receiver is ONE atomic op that owns lock+idempotency+mutation+checkpoint
 *  (4) fence token is a monotonic bigint PERSISTED and stale-rejected by the
 *      authoritative resource, not merely carried
 *  (5) DurableTx is opaque/backend-bound; the outbox ALLOCATES the sequence
 *      inside the tx, binding allocation+mutation+enqueue atomically
 *  (6) admission/backpressure is INSIDE the tx (append can abort the mutation);
 *      the publisher only drains and never sheds
 *  (7) contractVersion is the literal '1'; other values are rejected
 *  (8) genesis / epoch transition / duplicate history / resync are defined
 *  (9) mutations are a typed SanitizedMutation produced by a validated
 *      protocol-specific sanitizer, not prose
 */
import { createHash } from 'node:crypto';

/** (7) The only accepted contract version for v1. */
export const HA_OUTBOX_CONTRACT_VERSION = '1' as const;
export type ContractVersion = typeof HA_OUTBOX_CONTRACT_VERSION;

/** Domain separation string mixed into every digest (length-prefixed). */
export const HA_OUTBOX_DIGEST_DOMAIN = 'selfconnect/ha-outbox/v1' as const;

/** (1) Bounded identifier grammar: no control chars, no separators, bounded. */
export const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}$/;

/** Bounds for canonicalization (DoS-safe, deterministic). */
export const CANON_MAX_DEPTH = 64;
export const CANON_MAX_NODES = 10_000;

export class ContractValidationError extends Error {
  readonly code = 'ha_outbox_contract_validation';
  constructor(message: string) {
    super(message);
    this.name = 'ContractValidationError';
  }
}

function assertId(value: string, label: string): void {
  if (typeof value !== 'string' || !ID_PATTERN.test(value)) {
    throw new ContractValidationError(`${label} must match ${ID_PATTERN} (bounded, no separators)`);
  }
}

// ── (2) NORMATIVE canonicalization: RFC 8785 (JCS) restricted to RFC 7493 ─────
// Accepts only: null, boolean, safe-integer number, string, dense array, plain
// object. Rejects: undefined, non-finite/non-integer number, bigint, function,
// symbol, Date/Map/Set/typed arrays/class instances, sparse arrays, prototype-
// polluting keys. Object keys are sorted by UTF-16 code unit (JCS). Numbers are
// minimal decimal integers. Strings use JCS escaping. The OUTPUT BYTES are the
// language-neutral ground truth captured in the shared vectors; any conforming
// implementation in any language MUST reproduce them.

const JCS_STRING_ESCAPE: Record<string, string> = {
  '"': '\\"', '\\': '\\\\', '\b': '\\b', '\f': '\\f', '\n': '\\n', '\r': '\\r', '\t': '\\t',
};

function jcsString(s: string): string {
  let out = '"';
  for (const ch of s) {
    const code = ch.codePointAt(0)!;
    if (JCS_STRING_ESCAPE[ch]) out += JCS_STRING_ESCAPE[ch];
    else if (code < 0x20) out += '\\u' + code.toString(16).padStart(4, '0');
    else out += ch;
  }
  return out + '"';
}

function jcsNumber(n: number): string {
  // (I-JSON) integers only — floats/exponents are non-deterministic across
  // languages, so they are rejected rather than canonicalized.
  if (!Number.isSafeInteger(n)) {
    throw new ContractValidationError('only safe-integer numbers are canonicalizable');
  }
  return Object.is(n, -0) ? '0' : String(n);
}

function isPlainObject(v: object): boolean {
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

/** Produce the canonical JCS string of an I-JSON value (throws on non-conforming). */
export function canonicalize(value: unknown): string {
  let nodes = 0;
  const walk = (v: unknown, depth: number): string => {
    if (depth > CANON_MAX_DEPTH) throw new ContractValidationError('max canonicalization depth exceeded');
    if (++nodes > CANON_MAX_NODES) throw new ContractValidationError('max canonicalization node count exceeded');
    if (v === null) return 'null';
    switch (typeof v) {
      case 'boolean': return v ? 'true' : 'false';
      case 'number': return jcsNumber(v);
      case 'string': return jcsString(v);
      case 'undefined': throw new ContractValidationError('undefined is not canonicalizable');
      case 'bigint': throw new ContractValidationError('bigint is not canonicalizable');
      case 'function': throw new ContractValidationError('function is not canonicalizable');
      case 'symbol': throw new ContractValidationError('symbol is not canonicalizable');
    }
    if (Array.isArray(v)) {
      // reject sparse arrays (holes)
      for (let i = 0; i < v.length; i++) {
        if (!(i in v)) throw new ContractValidationError('sparse array (hole) is not canonicalizable');
      }
      return '[' + v.map((e) => walk(e, depth + 1)).join(',') + ']';
    }
    if (typeof v === 'object') {
      if (!isPlainObject(v)) throw new ContractValidationError('only plain objects are canonicalizable (no Date/Map/Set/class)');
      const obj = v as Record<string, unknown>;
      if (Object.prototype.hasOwnProperty.call(obj, '__proto__')) {
        throw new ContractValidationError('__proto__ key is rejected');
      }
      // JCS: sort by UTF-16 code units (default JS string comparison).
      const keys = Object.keys(obj).sort();
      return '{' + keys.map((k) => jcsString(k) + ':' + walk(obj[k], depth + 1)).join(',') + '}';
    }
    throw new ContractValidationError('value is not canonicalizable');
  };
  return walk(value, 0);
}

// ── (1) Length-prefixed digest framing ───────────────────────────────────────
function u32be(n: number): Buffer {
  const b = Buffer.allocUnsafe(4);
  b.writeUInt32BE(n >>> 0, 0);
  return b;
}

/**
 * (1)(2) NORMATIVE opDigest. Each field is fed to SHA-256 as
 * `u32be(utf8ByteLength(field)) || utf8(field)` in fixed order:
 *   domain, contractVersion, streamId, sourceEpoch, decimal(sequence),
 *   canonicalize(sanitizedMutation).
 * Length-prefixing removes any separator-collision ambiguity; the canonical
 * mutation is the JCS form above. The mutation MUST already be secret-stripped.
 */
export function canonicalOpDigest(input: {
  streamId: string;
  sourceEpoch: string;
  sequence: number;
  mutation: unknown;
}): string {
  assertId(input.streamId, 'streamId');
  assertId(input.sourceEpoch, 'sourceEpoch');
  if (!Number.isSafeInteger(input.sequence) || input.sequence < 0) {
    throw new ContractValidationError('sequence must be a non-negative safe integer');
  }
  const fields = [
    HA_OUTBOX_DIGEST_DOMAIN,
    HA_OUTBOX_CONTRACT_VERSION,
    input.streamId,
    input.sourceEpoch,
    String(input.sequence),
    canonicalize(input.mutation),
  ];
  const h = createHash('sha256');
  for (const f of fields) {
    const bytes = Buffer.from(f, 'utf8');
    h.update(u32be(bytes.length));
    h.update(bytes);
  }
  return h.digest('hex');
}

// ── Schema ────────────────────────────────────────────────────────────────

/** (9) Branded type: a mutation that a validated protocol sanitizer produced. */
export type SanitizedMutation<M> = M & { readonly __sanitized: unique symbol };

/** (9) Each protocol MUST provide a sanitizer that strips secrets and validates
 *  the result. `sanitize` throws if the raw payload cannot be made secret-free.
 *  `assertSanitized` re-validates on the receiver before apply. */
export interface MutationSanitizer<Raw, Clean> {
  sanitize(raw: Raw): SanitizedMutation<Clean>;
  assertSanitized(candidate: unknown): asserts candidate is SanitizedMutation<Clean>;
}

/** (a) Every record carries the literal contractVersion and versioned streamId. */
export interface OutboxRecordHeader {
  contractVersion: ContractVersion;
  streamId: string;
  sourceEpoch: string;
  sequence: number;
  opDigest: string;
}

export interface OutboxRecord<M = unknown> extends OutboxRecordHeader {
  /** (f)(9) secret-stripped, sanitizer-produced mutation. */
  mutation: SanitizedMutation<M>;
}

/** (c) idempotency key. */
export interface IdempotencyKey {
  streamId: string;
  sourceEpoch: string;
  sequence: number;
}
export function idempotencyKeyOf(h: OutboxRecordHeader): IdempotencyKey {
  return { streamId: h.streamId, sourceEpoch: h.sourceEpoch, sequence: h.sequence };
}

/** (7) Validate a header's version + IDs; throws on any non-conformance. */
export function assertHeaderConformant(h: OutboxRecordHeader): void {
  if (h.contractVersion !== HA_OUTBOX_CONTRACT_VERSION) {
    throw new ContractValidationError(`unsupported contractVersion ${String(h.contractVersion)}`);
  }
  assertId(h.streamId, 'streamId');
  assertId(h.sourceEpoch, 'sourceEpoch');
  if (!Number.isSafeInteger(h.sequence) || h.sequence < 0) {
    throw new ContractValidationError('sequence must be a non-negative safe integer');
  }
}

// ── (8) Genesis / epoch transition / resync ─────────────────────────────────
/** Genesis is sequence 0 of a source epoch. The first accepted mutation is
 *  sequence 1. A new sourceEpoch begins ONLY after detected loss/resync; its
 *  sequence restarts at 0 (genesis) and the receiver records the epoch order.
 *  A gap (received sequence > checkpoint+1) is never filled by assumption — it
 *  forces snapshot + tail resync under a NEW sourceEpoch. */
export interface EpochBoundary {
  streamId: string;
  /** Previous epoch this one supersedes, or null for the very first. */
  previousEpoch: string | null;
  newEpoch: string;
  /** Durable snapshot the new epoch's tail continues from. */
  snapshotSequence: number;
}

// ── Interfaces (type-only) ───────────────────────────────────────────────────

/** (5) Opaque, backend-bound transaction handle. Callers obtain it from the
 *  backend's `withTransaction`; it is NOT constructible by callers. The brand
 *  prevents forging a `{ id }` literal. */
export interface DurableTx {
  readonly __durableTx: unique symbol;
}

/** (4) Monotonic fencing token. Persisted and stale-rejected by the authoritative
 *  resource; carrying it is not enough. */
export type FenceToken = bigint;

export class StaleFenceError extends Error {
  readonly code = 'ha_outbox_stale_fence';
  constructor(readonly presented: FenceToken, readonly current: FenceToken) {
    super(`fence token ${presented} is stale; authoritative current is ${current}`);
    this.name = 'StaleFenceError';
  }
}

export class OutboxBackpressureError extends Error {
  readonly code = 'ha_outbox_backpressure';
  constructor(readonly policy: PublisherBackpressure) {
    super(`outbox admission rejected under backpressure policy '${policy}'`);
    this.name = 'OutboxBackpressureError';
  }
}

/**
 * (5)(6) The outbox ALLOCATES the sequence and enqueues WITHIN the caller's
 * durable transaction, binding sequence-allocation + mutation + outbox row
 * atomically. Admission/backpressure is enforced HERE, inside the tx: if the
 * outbox is at its declared bound, it throws OutboxBackpressureError which
 * aborts the caller's transaction — the authoritative mutation fails closed.
 * The authoritative resource persists+validates the fence token and throws
 * StaleFenceError if it is not current. Never sheds.
 */
export interface DurableOutbox<M = unknown> {
  appendInTx(
    tx: DurableTx,
    input: { streamId: string; mutation: SanitizedMutation<M>; fenceToken: FenceToken },
  ): Promise<OutboxRecordHeader>;
}

/** (6)(g) The publisher ONLY drains committed rows: retries idempotently,
 *  records ACKs, never silently drops, never sheds. Backpressure is handled at
 *  admission (append), not here. */
export type PublisherBackpressure = 'fail-authoritative-mutation' | 'quarantine';
export interface OutboxPublisher {
  drainOnce(): Promise<{ published: number; acked: number }>;
  readonly backpressure: PublisherBackpressure;
}

/** Receiver decision returned by the single atomic operation. */
export type ReceiverDecision =
  | 'applied'        // fresh, in-order, verified → mutation+checkpoint committed
  | 'duplicate-ok'   // (c) same key AND identical digest → idempotent no-op
  | 'reject-gap'     // sequence > checkpoint+1 → resync required
  | 'reject-fork'    // (c) same key, different digest → fork/tamper
  | 'reject-stale'   // sequence <= checkpoint → replay/rollback
  | 'reject-epoch'   // unknown/backward source epoch
  | 'reject-fence';  // (4) stale fence token

/**
 * (3) ONE atomic operation that owns: the row/stream LOCK, the idempotency
 * check, digest+fence verification, the mutation apply, and the durable
 * checkpoint advance — all in a single transaction. There is deliberately NO
 * separate classify() (its TOCTOU permitted double-apply / HOTP double-consume).
 * Returns the decision it committed under lock.
 */
export interface ReceiverCheckpoint<M = unknown> {
  verifyAndApplyInTx(
    tx: DurableTx,
    record: OutboxRecord<M>,
    fenceToken: FenceToken,
  ): Promise<ReceiverDecision>;
}

/**
 * (4)(h) EXTERNAL fence whose token is PERSISTED and stale-rejected by the
 * authoritative resource. Not a process-local predicate; carrying the token is
 * not enough — the outbox/receiver resource itself must reject stale tokens
 * atomically (StaleFenceError). Promotion also requires durable
 * source==receiver convergence checked by the caller.
 */
export interface PromotionFence {
  /** Acquire/renew; returns a strictly monotonic token the resource persists. */
  acquire(streamId: string): Promise<FenceToken>;
  /** The authoritative resource's current persisted token (for convergence checks). */
  current(streamId: string): Promise<FenceToken>;
}
