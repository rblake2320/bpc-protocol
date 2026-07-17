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
/** Per-string and total canonical UTF-8 byte bounds — kept far below the u32
 *  length-prefix ceiling so a single huge string cannot overflow the framing
 *  or DoS the hash. */
export const CANON_MAX_STRING_BYTES = 1 << 16; // 65,536
export const CANON_MAX_TOTAL_BYTES = 1 << 20;  // 1,048,576
/** u32 length-prefix ceiling (fields must be strictly below this). */
const U32_CEIL = 0x1_0000_0000;
/** Canonical fence token: non-negative decimal, no leading zeros. */
export const FENCE_TOKEN_PATTERN = /^(0|[1-9][0-9]{0,38})$/;
/** opDigest: 64 lowercase hex. */
const HEX64 = /^[0-9a-f]{64}$/;

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

/** Reject strings containing a lone/unpaired UTF-16 surrogate. Otherwise UTF-8
 *  encoding would replace it with U+FFFD, so two distinct strings could hash
 *  identically. Applies to values AND object keys. */
function assertNoLoneSurrogate(s: string): void {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const n = s.charCodeAt(i + 1);
      if (!(n >= 0xdc00 && n <= 0xdfff)) throw new ContractValidationError('lone high surrogate is not canonicalizable');
      i++; // valid pair
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      throw new ContractValidationError('lone low surrogate is not canonicalizable');
    }
  }
}

function utf8Len(s: string): number {
  return Buffer.byteLength(s, 'utf8');
}

function jcsString(s: string): string {
  assertNoLoneSurrogate(s);
  if (utf8Len(s) > CANON_MAX_STRING_BYTES) throw new ContractValidationError('string exceeds CANON_MAX_STRING_BYTES');
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
      for (let i = 0; i < v.length; i++) {
        if (!(i in v)) throw new ContractValidationError('sparse array (hole) is not canonicalizable');
      }
      return '[' + v.map((e) => walk(e, depth + 1)).join(',') + ']';
    }
    if (typeof v === 'object') {
      if (!isPlainObject(v)) throw new ContractValidationError('only plain objects are canonicalizable (no Date/Map/Set/class)');
      // (3) reject own symbol keys and any accessor / non-data properties;
      // reading a getter would execute code and break determinism.
      if (Object.getOwnPropertySymbols(v).length > 0) throw new ContractValidationError('symbol keys are not canonicalizable');
      const names = Object.getOwnPropertyNames(v);
      for (const k of names) {
        const d = Object.getOwnPropertyDescriptor(v, k)!;
        if (!('value' in d)) throw new ContractValidationError(`accessor/non-data property '${k}' is not canonicalizable`);
        if (k === '__proto__') throw new ContractValidationError('__proto__ key is rejected');
      }
      const obj = v as Record<string, unknown>;
      const keys = names.sort(); // JCS: UTF-16 code-unit order
      return '{' + keys.map((k) => (assertNoLoneSurrogate(k), jcsString(k) + ':' + walk(obj[k], depth + 1))).join(',') + '}';
    }
    throw new ContractValidationError('value is not canonicalizable');
  };
  const out = walk(value, 0);
  // (2) total byte bound (per-string bound is enforced in jcsString).
  if (utf8Len(out) > CANON_MAX_TOTAL_BYTES) throw new ContractValidationError('canonical form exceeds CANON_MAX_TOTAL_BYTES');
  return out;
}

// ── (1) Length-prefixed digest framing ───────────────────────────────────────
function u32be(n: number): Buffer {
  // (2) reject fields at/over the u32 ceiling instead of wrapping via >>> 0.
  if (!Number.isInteger(n) || n < 0 || n >= U32_CEIL) {
    throw new ContractValidationError('field byte length exceeds the u32 framing ceiling');
  }
  const b = Buffer.allocUnsafe(4);
  b.writeUInt32BE(n, 0);
  return b;
}

/** (5) canonical decimal for the fence token bound into the digest. */
function assertFenceToken(t: string): void {
  if (typeof t !== 'string' || !FENCE_TOKEN_PATTERN.test(t)) {
    throw new ContractValidationError('fenceToken must be canonical non-negative decimal (no leading zeros)');
  }
}

/**
 * (1)(2)(5) NORMATIVE opDigest. Each field is fed to SHA-256 as
 * `u32be(utf8ByteLength(field)) || utf8(field)` in fixed order:
 *   domain, contractVersion, streamId, sourceEpoch, decimal(sequence),
 *   decimal(fenceToken), canonicalize(sanitizedMutation).
 * The fence token is BOUND into the digest so a record cannot be paired with a
 * different token. Length-prefixing removes separator-collision ambiguity. The
 * mutation MUST already be secret-stripped.
 */
export function canonicalOpDigest(input: {
  streamId: string;
  sourceEpoch: string;
  sequence: number;
  fenceToken: string;
  mutation: unknown;
}): string {
  assertId(input.streamId, 'streamId');
  assertNoLoneSurrogate(input.streamId);
  assertId(input.sourceEpoch, 'sourceEpoch');
  assertNoLoneSurrogate(input.sourceEpoch);
  if (!Number.isSafeInteger(input.sequence) || input.sequence < 0) {
    throw new ContractValidationError('sequence must be a non-negative safe integer');
  }
  assertFenceToken(input.fenceToken);
  const fields = [
    HA_OUTBOX_DIGEST_DOMAIN,
    HA_OUTBOX_CONTRACT_VERSION,
    input.streamId,
    input.sourceEpoch,
    String(input.sequence),
    input.fenceToken,
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

/** (9)(10) Branded type: a mutation a validated protocol sanitizer produced.
 *  The brand is TYPE-LEVEL only (erased at runtime); binding is enforced at
 *  RUNTIME by the outbox/receiver invoking the sanitizer (see (10)). */
export type SanitizedMutation<M> = M & { readonly __sanitized: unique symbol };

/** (9)(10) Each protocol MUST provide a sanitizer that strips secrets and
 *  validates the result. `sanitize` throws if the raw payload cannot be made
 *  secret-free. `assertSanitized` re-validates on the receiver before apply and
 *  MUST throw on any residual secret / malformed shape. */
export interface MutationSanitizer<Raw, Clean> {
  sanitize(raw: Raw): SanitizedMutation<Clean>;
  assertSanitized(candidate: unknown): asserts candidate is SanitizedMutation<Clean>;
}

/** (a)(5) Every record carries literal contractVersion, versioned streamId, and
 *  the canonical-decimal fence token bound into its digest. */
export interface OutboxRecordHeader {
  contractVersion: ContractVersion;
  streamId: string;
  sourceEpoch: string;
  sequence: number;
  /** (5) canonical non-negative decimal fence token, bound into opDigest. */
  fenceToken: string;
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

/** (a)(4)(5) Validate a header fully; throws on any non-conformance. */
export function assertHeaderConformant(h: OutboxRecordHeader): void {
  if (h.contractVersion !== HA_OUTBOX_CONTRACT_VERSION) {
    throw new ContractValidationError(`unsupported contractVersion ${String(h.contractVersion)}`);
  }
  assertId(h.streamId, 'streamId');
  assertNoLoneSurrogate(h.streamId);
  assertId(h.sourceEpoch, 'sourceEpoch');
  assertNoLoneSurrogate(h.sourceEpoch);
  if (!Number.isSafeInteger(h.sequence) || h.sequence < 0) {
    throw new ContractValidationError('sequence must be a non-negative safe integer');
  }
  assertFenceToken(h.fenceToken);
  if (!HEX64.test(h.opDigest)) throw new ContractValidationError('opDigest must be 64 lowercase hex');
}

// ── (9) Sequence semantics + typed, digested, fenced epoch transition ─────────
// Genesis = sequence 0 of a source epoch (no mutation). The first mutation is
// sequence 1. A gap (received > checkpoint+1) is never filled by assumption; it
// forces snapshot + tail resync under a governed FORWARD epoch transition.

export interface EpochTransitionRecord {
  contractVersion: ContractVersion;
  streamId: string;
  /** epoch being superseded (must be the current durable epoch). */
  fromEpoch: string;
  /** new epoch — strictly forward; a receiver rejects a non-forward toEpoch. */
  toEpoch: string;
  /** durable snapshot sequence the new epoch's tail continues from. */
  snapshotSequence: number;
  /** (5) fence token bound into the transition digest. */
  fenceToken: string;
  /** digest over the above (excluding this field). */
  transitionDigest: string;
}

/** (9) NORMATIVE digest for an epoch transition (same length-prefixed framing). */
export function epochTransitionDigest(input: {
  streamId: string; fromEpoch: string; toEpoch: string; snapshotSequence: number; fenceToken: string;
}): string {
  assertId(input.streamId, 'streamId'); assertNoLoneSurrogate(input.streamId);
  assertId(input.fromEpoch, 'fromEpoch'); assertNoLoneSurrogate(input.fromEpoch);
  assertId(input.toEpoch, 'toEpoch'); assertNoLoneSurrogate(input.toEpoch);
  if (!Number.isSafeInteger(input.snapshotSequence) || input.snapshotSequence < 0) {
    throw new ContractValidationError('snapshotSequence must be a non-negative safe integer');
  }
  assertFenceToken(input.fenceToken);
  const fields = [
    HA_OUTBOX_DIGEST_DOMAIN + '/epoch-transition',
    HA_OUTBOX_CONTRACT_VERSION, input.streamId, input.fromEpoch, input.toEpoch,
    String(input.snapshotSequence), input.fenceToken,
  ];
  const h = createHash('sha256');
  for (const f of fields) { const b = Buffer.from(f, 'utf8'); h.update(u32be(b.length)); h.update(b); }
  return h.digest('hex');
}

// ── (7) Backend-bound transaction handle ─────────────────────────────────────
/** Opaque transaction handle parameterized by a BACKEND brand so a tx obtained
 *  from backend A does not typecheck for backend B. Each backend declares its
 *  own unique brand type; callers cannot forge one. */
export interface DurableTx<TBackend = unknown> {
  readonly __backend: TBackend;
}

/** (4) Monotonic fencing token. Persisted + stale-rejected by the authoritative
 *  resource; the canonical-decimal form is what is bound into digests. */
export type FenceToken = bigint;
export function fenceTokenToDecimal(t: FenceToken): string {
  if (typeof t !== 'bigint' || t < 0n) throw new ContractValidationError('fenceToken must be a non-negative bigint');
  return t.toString(10);
}

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
 * (5)(6)(10)(11) The outbox holds the protocol's `sanitizer` and, within the
 * caller's backend-bound transaction, sanitizes the raw mutation, allocates the
 * sequence, binds the fence token, and enqueues the outbox row — all atomically.
 * (10) The raw mutation is sanitized HERE (runtime binding), never trusted from
 * the caller as pre-sanitized. (11) Admission is inside the tx: the authoritative
 * mutation CANNOT commit without a durable admitted outbox row — at the bound it
 * throws OutboxBackpressureError which aborts the tx; under the `quarantine`
 * policy every mutation is refused (fail closed) until the backlog drains below
 * the bound. Never sheds. The authoritative resource persists+validates the
 * fence token (StaleFenceError).
 */
export interface DurableOutbox<Raw = unknown, Clean = Raw, TBackend = unknown> {
  readonly sanitizer: MutationSanitizer<Raw, Clean>;
  appendInTx(
    tx: DurableTx<TBackend>,
    input: { streamId: string; rawMutation: Raw; fenceToken: FenceToken },
  ): Promise<OutboxRecordHeader>;
}

/** (6)(g)(11) The publisher ONLY drains committed rows: retries idempotently,
 *  records ACKs, never sheds. `quarantine` = a declared fail-closed mode where
 *  no authoritative mutation commits until the backlog drains; `fail-
 *  authoritative-mutation` = each over-bound append aborts its own tx. */
export type PublisherBackpressure = 'fail-authoritative-mutation' | 'quarantine';
export interface OutboxPublisher {
  drainOnce(): Promise<{ published: number; acked: number }>;
  readonly backpressure: PublisherBackpressure;
}

export type ReceiverDecision =
  | 'applied' | 'duplicate-ok' | 'reject-gap' | 'reject-fork'
  | 'reject-stale' | 'reject-epoch' | 'reject-fence' | 'reject-unsanitized';

/**
 * (3)(10) ONE atomic operation that owns the row LOCK, idempotency check,
 * digest+fence verification, the sanitizer re-check (`assertSanitized` — rejects
 * an unsanitized/secret-bearing record as `reject-unsanitized`), mutation apply,
 * and durable checkpoint advance — all in one transaction. No separate classify.
 */
export interface ReceiverCheckpoint<Clean = unknown, TBackend = unknown> {
  readonly sanitizer: Pick<MutationSanitizer<unknown, Clean>, 'assertSanitized'>;
  verifyAndApplyInTx(
    tx: DurableTx<TBackend>,
    record: OutboxRecord<Clean>,
    fenceToken: FenceToken,
  ): Promise<ReceiverDecision>;
  /** (9) authorized, forward-only epoch transition, atomic under the fence. */
  transitionEpochInTx(tx: DurableTx<TBackend>, record: EpochTransitionRecord): Promise<void>;
}

/**
 * (4)(h) EXTERNAL fence whose token is PERSISTED and stale-rejected by the
 * authoritative resource (StaleFenceError). Not a process-local predicate.
 */
export interface PromotionFence {
  acquire(streamId: string): Promise<FenceToken>;
  current(streamId: string): Promise<FenceToken>;
}

// ── (8) TSK-specific extension (present in both repos; bpc leaves it unused) ──
/** A signed, hash-linked stream head committed atomically with a tumbler
 *  mutation (tsk#10). `prevHeadDigest` links to the previous head; `headDigest`
 *  covers this record; `signature` authenticates it. */
export interface SignedStreamHead {
  streamId: string;
  sequence: number;
  prevHeadDigest: string; // 64 hex, or the genesis head
  headDigest: string;     // 64 hex over (streamId, sequence, prevHeadDigest, opDigest)
  signature: string;      // detached signature over headDigest (base64url)
}

/** The tumbler HOTP mutation carries a strictly-increasing counter that MUST
 *  never be consumed twice (I2). Secret material is stripped by the sanitizer. */
export interface TskHotpMutation {
  tumblerId: string;
  /** HOTP counter — strictly increasing per tumbler; never double-consumed. */
  counter: number;
}
export type HotpMutationSanitizer = MutationSanitizer<TskHotpMutation, TskHotpMutation>;

/** (8) Atomic tumbler apply: verify + consume HOTP counter (reject double-
 *  consume) + append the signed/hash-linked head + advance the durable
 *  checkpoint, ALL in one transaction. */
export interface TskReceiverCheckpoint<TBackend = unknown>
  extends ReceiverCheckpoint<TskHotpMutation, TBackend> {
  verifyAndApplyTumblerInTx(
    tx: DurableTx<TBackend>,
    record: OutboxRecord<TskHotpMutation>,
    head: SignedStreamHead,
    fenceToken: FenceToken,
  ): Promise<ReceiverDecision>;
}

/** (8) NORMATIVE head digest for the signed/hash-linked stream head. */
export function streamHeadDigest(input: {
  streamId: string; sequence: number; prevHeadDigest: string; opDigest: string;
}): string {
  assertId(input.streamId, 'streamId'); assertNoLoneSurrogate(input.streamId);
  if (!Number.isSafeInteger(input.sequence) || input.sequence < 0) {
    throw new ContractValidationError('sequence must be a non-negative safe integer');
  }
  if (!HEX64.test(input.prevHeadDigest)) throw new ContractValidationError('prevHeadDigest must be 64 lowercase hex');
  if (!HEX64.test(input.opDigest)) throw new ContractValidationError('opDigest must be 64 lowercase hex');
  const fields = [
    HA_OUTBOX_DIGEST_DOMAIN + '/tsk-stream-head',
    HA_OUTBOX_CONTRACT_VERSION, input.streamId, String(input.sequence),
    input.prevHeadDigest, input.opDigest,
  ];
  const h = createHash('sha256');
  for (const f of fields) { const b = Buffer.from(f, 'utf8'); h.update(u32be(b.length)); h.update(b); }
  return h.digest('hex');
}
