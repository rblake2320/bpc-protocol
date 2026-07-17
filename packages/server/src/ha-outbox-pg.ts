/**
 * PostgreSQL implementation of the HA durable-outbox contract (#16).
 *
 * Single-authority mechanism: transactionally-coupled authoritative mutation +
 * outbox append with in-tx sequence allocation and fence validation; a durable
 * publisher that uses a bounded CLAIM-LEASE (short claim tx → network delivery
 * OUTSIDE any tx/lock → short ack tx) so it never holds row locks across the
 * network and never sheds; and a receiver that verifies+applies+checkpoints
 * idempotently under one lock, against an INDEPENDENT receiver checkpoint.
 * Conforms to `ha-outbox-contract.ts`.
 *
 * BOUNDARY: this file is the mechanism + its adversarial LOGIC tests (snapshot
 * fake). It makes NO crash-durable-HA claim on its own, and the fake CANNOT
 * establish lock/isolation/lease/concurrency behavior — those are proven only
 * by the real-PostgreSQL concurrency suite (tests/ha-outbox-pg.realpg.test.ts,
 * gated on a live server). Issue #16 stays OPEN until the two-node
 * PostgreSQL(+Redis) failover/split-brain drill passes with recorded RPO/RTO.
 */
import { randomUUID, timingSafeEqual } from 'node:crypto';
import {
  ContractValidationError,
  OutboxBackpressureError,
  StaleFenceError,
  assertHeaderConformant,
  canonicalOpDigest,
  fenceTokenToDecimal,
  type DurableOutbox,
  type DurableTx,
  type EpochTransitionAuthorizer,
  type FenceToken,
  type MutationSanitizer,
  type OutboxRecord,
  type OutboxRecordHeader,
  type PromotionFence,
  type PublisherBackpressure,
  type ReceiverCheckpoint,
  type ReceiverDecision,
  type SanitizedMutation,
} from './ha-outbox-contract.js';

/** Backend brand for this implementation — makes a DurableTx from this backend
 *  distinct from any other backend's tx at the type level. */
export interface PgBackend {
  readonly __pgHaOutbox: unique symbol;
}
export type PgTx = DurableTx<PgBackend>;

/** A transaction-scoped executor (all queries run inside one DB transaction).
 *  `rowCount` is the number of rows the statement affected/returned — REQUIRED
 *  so write effects can be asserted (a silent 0-row UPDATE is a fault, not a
 *  no-op). node-postgres already returns it. */
export interface PgExecutor {
  query(sql: string, params?: unknown[]): Promise<{ rows: Record<string, unknown>[]; rowCount: number }>;
}

/** Runs `fn` inside a single SERIALIZABLE DB transaction: BEGIN ISOLATION LEVEL
 *  SERIALIZABLE, run, COMMIT; ROLLBACK (and rethrow) on any throw. Serializable
 *  is not merely a comment: every critical tx re-asserts it at runtime via
 *  `assertSerializable`, so a read-committed transactor is rejected. */
export interface PgTransactor {
  transaction<T>(fn: (exec: PgExecutor) => Promise<T>): Promise<T>;
}

// The opaque DurableTx carries no public members; the real executor is held in
// a module-private WeakMap so it never leaks into the contract type and cannot
// be reached by callers holding only the branded handle.
const TX_EXECUTOR = new WeakMap<object, PgExecutor>();

function execOf(tx: PgTx): PgExecutor {
  const e = TX_EXECUTOR.get(tx as unknown as object);
  if (!e) throw new ContractValidationError('DurableTx not bound to a PostgreSQL transaction (forged or foreign tx)');
  return e;
}

/** Constant-time equality for two 64-hex digests (equal length by construction). */
function digestEquals(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'));
}

/** Parse a DB numeric/bigint into a contract-safe non-negative JS integer, or
 *  throw a ContractValidationError — never silently truncate an unsafe bigint
 *  via Number(), and never leak a native RangeError/SyntaxError from BigInt(). */
function safeSeq(v: unknown, label: string): number {
  let b: bigint;
  try { b = BigInt(String(v)); }
  catch { throw new ContractValidationError(`${label} is not an integer: ${String(v)}`); }
  if (b < 0n || b > BigInt(Number.MAX_SAFE_INTEGER)) throw new ContractValidationError(`${label} out of safe-integer range: ${b.toString()}`);
  return Number(b);
}

/** Assert a write statement affected EXACTLY one row (allocator advance, claim,
 *  ack, checkpoint advance, fence acquire). Any other count is a fault. */
function affectedOne(res: { rowCount: number }, label: string): void {
  if (res.rowCount !== 1) throw new ContractValidationError(`${label}: expected exactly 1 affected row, got ${res.rowCount}`);
}

/** (HIGH4) Enforce SERIALIZABLE at the entry of every critical tx. A transactor
 *  that opened READ COMMITTED (or anything else) is rejected — isolation is a
 *  runtime invariant, not a comment. */
async function assertSerializable(exec: PgExecutor): Promise<void> {
  const rows = (await exec.query('SHOW transaction_isolation')).rows;
  const level = String(rows[0]?.transaction_isolation ?? '').toLowerCase();
  if (level !== 'serializable') throw new ContractValidationError(`critical tx requires SERIALIZABLE isolation; got '${level}'`);
}

/** Mint a `DurableTx<PgBackend>` bound to a live executor. The backend is the
 *  trusted minter of tx handles (the contract's brand is unforgeable by outside
 *  callers); a caller running its own `db.transaction` uses this to obtain a
 *  handle for `appendInTx` / `verifyAndApplyInTx`. */
export function createBoundTx(exec: PgExecutor): PgTx {
  const tx = Object.freeze({}) as unknown as PgTx;
  TX_EXECUTOR.set(tx as unknown as object, exec);
  return tx;
}

/**
 * DDL for the outbox tables. Source-side and receiver-side checkpoints are
 * SEPARATE tables (independent authorities); rows carry a claim-lease. Every
 * numeric/text column carries a CHECK so a malformed row cannot be persisted:
 *  - sequence non-negative and within JS safe-integer range,
 *  - fence_token non-negative,
 *  - op_digest exactly 64 lowercase hex,
 *  - stream_id / source_epoch non-empty and bounded.
 */
export const HA_OUTBOX_PG_SCHEMA = `
CREATE TABLE IF NOT EXISTS ha_outbox_fence (
  stream_id     text PRIMARY KEY CHECK (length(stream_id) BETWEEN 1 AND 512),
  fence_token   numeric NOT NULL DEFAULT 0 CHECK (fence_token >= 0)
);
-- Source-side allocator checkpoint (last ALLOCATED sequence).
CREATE TABLE IF NOT EXISTS ha_outbox_source_checkpoint (
  stream_id     text PRIMARY KEY CHECK (length(stream_id) BETWEEN 1 AND 512),
  source_epoch  text NOT NULL CHECK (length(source_epoch) BETWEEN 1 AND 512),
  epoch_index   bigint NOT NULL DEFAULT 0 CHECK (epoch_index >= 0),
  sequence      bigint NOT NULL DEFAULT 0 CHECK (sequence >= 0 AND sequence <= 9007199254740991)
);
-- Receiver-side applied checkpoint (last APPLIED sequence) — a DISTINCT authority.
CREATE TABLE IF NOT EXISTS ha_outbox_receiver_checkpoint (
  stream_id     text PRIMARY KEY CHECK (length(stream_id) BETWEEN 1 AND 512),
  source_epoch  text NOT NULL CHECK (length(source_epoch) BETWEEN 1 AND 512),
  epoch_index   bigint NOT NULL DEFAULT 0 CHECK (epoch_index >= 0),
  sequence      bigint NOT NULL DEFAULT 0 CHECK (sequence >= 0 AND sequence <= 9007199254740991),
  last_digest   text NOT NULL DEFAULT '' CHECK (last_digest = '' OR last_digest ~ '^[0-9a-f]{64}$')
);
CREATE TABLE IF NOT EXISTS ha_outbox_rows (
  stream_id     text NOT NULL CHECK (length(stream_id) BETWEEN 1 AND 512),
  source_epoch  text NOT NULL CHECK (length(source_epoch) BETWEEN 1 AND 512),
  sequence      bigint NOT NULL CHECK (sequence >= 1 AND sequence <= 9007199254740991),
  fence_token   numeric NOT NULL CHECK (fence_token >= 0),
  op_digest     text NOT NULL CHECK (op_digest ~ '^[0-9a-f]{64}$'),
  mutation      jsonb NOT NULL,                   -- secret-stripped
  claim_token   text,                             -- current publisher lease holder
  claim_until   timestamptz,                      -- lease expiry (retryable after)
  published_at  timestamptz,
  acked_at      timestamptz,
  PRIMARY KEY (stream_id, source_epoch, sequence)
);
CREATE INDEX IF NOT EXISTS ha_outbox_rows_claimable
  ON ha_outbox_rows (stream_id, sequence) WHERE acked_at IS NULL;
-- Receiver-side durable applied history (independent of the source outbox
-- table) so duplicate/fork/stale decisions survive on the receiver.
CREATE TABLE IF NOT EXISTS ha_outbox_applied (
  stream_id     text NOT NULL CHECK (length(stream_id) BETWEEN 1 AND 512),
  source_epoch  text NOT NULL CHECK (length(source_epoch) BETWEEN 1 AND 512),
  sequence      bigint NOT NULL CHECK (sequence >= 1 AND sequence <= 9007199254740991),
  op_digest     text NOT NULL CHECK (op_digest ~ '^[0-9a-f]{64}$'),
  PRIMARY KEY (stream_id, source_epoch, sequence)
);
`;

export interface PgOutboxOptions<Raw, Clean> {
  streamId: string;
  sanitizer: MutationSanitizer<Raw, Clean>;
  /** Max unpublished/unacked rows before admission fails closed. */
  maxPendingRows: number;
  /** Backpressure policy surfaced to the publisher contract. */
  backpressure: PublisherBackpressure;
}

/**
 * The source-side durable outbox. `withOutboxTx` opens ONE serializable DB
 * transaction and yields a bound `DurableTx`; `appendInTx` runs entirely inside
 * it: fence check, admission (bounded), sequence allocation, sanitize, digest,
 * and row insert all commit or roll back together with the caller's mutation.
 */
export class PgDurableOutbox<Raw, Clean> implements DurableOutbox<Raw, Clean, PgBackend> {
  readonly sanitizer: MutationSanitizer<Raw, Clean>;
  constructor(private readonly db: PgTransactor, private readonly opts: PgOutboxOptions<Raw, Clean>) {
    if (!Number.isSafeInteger(opts.maxPendingRows) || opts.maxPendingRows <= 0) {
      throw new ContractValidationError('maxPendingRows must be a positive safe integer');
    }
    this.sanitizer = opts.sanitizer;
  }

  /** Open a durable tx and run `fn` with the bound handle. The caller performs
   *  its authoritative mutation and `appendInTx` inside `fn`; both commit atomically. */
  async withOutboxTx<T>(fn: (tx: PgTx, exec: PgExecutor) => Promise<T>): Promise<T> {
    return this.db.transaction(async (exec) => {
      await assertSerializable(exec);
      return fn(createBoundTx(exec), exec);
    });
  }

  async appendInTx(
    tx: PgTx,
    input: { streamId: string; rawMutation: Raw; fenceToken: FenceToken },
  ): Promise<OutboxRecordHeader> {
    const exec = execOf(tx);
    const streamId = input.streamId;
    if (streamId !== this.opts.streamId) throw new ContractValidationError('streamId mismatch for this outbox');
    const fenceDecimal = fenceTokenToDecimal(input.fenceToken);

    // (h) validate the presented fence token against the authoritative persisted
    // token under a row lock; stale token fails closed.
    const fenceRows = (await exec.query('SELECT fence_token FROM ha_outbox_fence WHERE stream_id = $1 FOR UPDATE', [streamId])).rows;
    if (!fenceRows.length) throw new ContractValidationError('no authoritative fence row — stream not provisioned (fail closed)');
    const persistedFence = BigInt(String(fenceRows[0].fence_token));
    if (input.fenceToken !== persistedFence) throw new StaleFenceError(input.fenceToken, persistedFence);

    // (11) admission INSIDE the tx: over the bound → abort the mutation.
    const pending = safeSeq((await exec.query('SELECT count(*)::bigint AS n FROM ha_outbox_rows WHERE stream_id = $1 AND acked_at IS NULL', [streamId])).rows[0].n, 'pending-count');
    if (pending >= this.opts.maxPendingRows) throw new OutboxBackpressureError(this.opts.backpressure);

    // (i) allocate the next sequence within the tx (source checkpoint = allocator).
    const cpRows = (await exec.query('SELECT source_epoch, sequence FROM ha_outbox_source_checkpoint WHERE stream_id = $1 FOR UPDATE', [streamId])).rows;
    if (!cpRows.length) throw new ContractValidationError('stream not provisioned (no source checkpoint row)');
    const sourceEpoch = String(cpRows[0].source_epoch);
    // (HIGH6) safe-integer allocation — never Number(bigint)+1 on an unsafe value.
    const cur = safeSeq(cpRows[0].sequence, 'source.checkpoint.sequence');
    if (cur >= Number.MAX_SAFE_INTEGER) throw new ContractValidationError('source sequence exhausted safe-integer range');
    const nextSeq = cur + 1;

    // (10) sanitize the RAW mutation here (runtime binding); digest the sanitized form.
    const mutation = this.sanitizer.sanitize(input.rawMutation);
    const opDigest = canonicalOpDigest<Clean>({ streamId, sourceEpoch, sequence: nextSeq, fenceToken: fenceDecimal, mutation });

    const ins = await exec.query(
      'INSERT INTO ha_outbox_rows (stream_id, source_epoch, sequence, fence_token, op_digest, mutation) VALUES ($1,$2,$3,$4,$5,$6)',
      [streamId, sourceEpoch, nextSeq, fenceDecimal, opDigest, JSON.stringify(mutation)],
    );
    affectedOne(ins, 'outbox row insert');
    const upd = await exec.query('UPDATE ha_outbox_source_checkpoint SET sequence = $2 WHERE stream_id = $1', [streamId, nextSeq]);
    affectedOne(upd, 'source checkpoint advance');

    const header: OutboxRecordHeader = { contractVersion: '1', streamId, sourceEpoch, sequence: nextSeq, fenceToken: fenceDecimal, opDigest };
    assertHeaderConformant(header);
    return header;
  }
}

/** (#4/HIGH2) Record-bound acknowledgement the receiver returns. The tuple/
 *  digest fields prove ECHO only; `receiverId`/`keyId`/`issuedAt`/`signature`
 *  let an `AckReceiptVerifier` prove the ACK actually came from the authorized
 *  receiver over the record. */
export interface AckReceipt {
  streamId: string;
  sourceEpoch: string;
  sequence: number;
  opDigest: string;
  receiverId: string;
  keyId: string;
  issuedAt: string;
  signature: string;
}
/** (HIGH2) Verifies a receipt is a genuine, authorized acknowledgement of THIS
 *  record. MUST throw on an invalid signature, an unknown/unauthorized key, or
 *  when the verifying material is unavailable (fail-closed). A field-perfect but
 *  unsigned/forged receipt MUST be rejected here. */
export interface AckReceiptVerifier {
  verify(receipt: AckReceipt, record: OutboxRecord<unknown>): Promise<void>;
}
/** Transport delivers a record and returns the receiver's ACK receipt. A throw
 *  (or a receipt that fails verification / does not match) leaves the row
 *  unacked — the row is NEVER acked on call-completion alone. */
export interface OutboxTransport {
  deliverAndAwaitAck(record: OutboxRecord<unknown>): Promise<AckReceipt>;
}

export interface PgPublisherOptions {
  /** Max rows claimed per drain (bounds lock scope + batch size). */
  batchSize: number;
  /** Lease duration in ms; a claimed-but-unacked row is retryable after this. */
  leaseMs: number;
}

/**
 * Durable publisher with a BOUNDED CLAIM-LEASE (HIGH1). One drain is:
 *   1) short serializable tx: claim ≤ batchSize claimable rows (SKIP LOCKED),
 *      stamp a unique claim_token + claim_until, COMMIT — releases all locks.
 *   2) for each claimed row: revalidate + recompute digest, deliver over the
 *      transport and await an ACK receipt, OUTSIDE any DB tx (no lock held
 *      across the network), verify the receipt (crypto + record-bound).
 *   3) short serializable tx: ACK exactly this row iff it is still unacked AND
 *      still holds our claim_token AND op_digest matches — assert 1 row.
 * A crash after (1)/before (3) leaves the lease to expire and be reclaimed; the
 * receiver is idempotent, so redelivery is safe. Never sheds.
 */
export class PgDurablePublisher<Clean> {
  private readonly batchSize: number;
  private readonly leaseMs: number;
  constructor(
    private readonly db: PgTransactor,
    private readonly streamId: string,
    private readonly transport: OutboxTransport,
    readonly backpressure: PublisherBackpressure,
    /** (#5) sanitizer to revalidate each DB row before publishing. */
    private readonly sanitizer: Pick<MutationSanitizer<unknown, Clean>, 'assertSanitized'>,
    /** (HIGH2) verifier for the receiver's ACK receipt — REQUIRED (fail-closed). */
    private readonly ackVerifier: AckReceiptVerifier,
    opts: PgPublisherOptions = { batchSize: 64, leaseMs: 30_000 },
  ) {
    if (!Number.isSafeInteger(opts.batchSize) || opts.batchSize <= 0) throw new ContractValidationError('batchSize must be a positive safe integer');
    if (!Number.isSafeInteger(opts.leaseMs) || opts.leaseMs <= 0) throw new ContractValidationError('leaseMs must be a positive safe integer');
    this.batchSize = opts.batchSize;
    this.leaseMs = opts.leaseMs;
  }

  async drainOnce(): Promise<{ published: number; acked: number }> {
    const claimToken = randomUUID();
    // (1) bounded claim — short tx, releases locks on COMMIT.
    const claimed = await this.db.transaction(async (exec) => {
      await assertSerializable(exec);
      return (await exec.query(
        `WITH cte AS (
           SELECT stream_id, source_epoch, sequence FROM ha_outbox_rows
           WHERE stream_id = $1 AND acked_at IS NULL AND (claim_until IS NULL OR claim_until < now())
           ORDER BY sequence ASC LIMIT $2 FOR UPDATE SKIP LOCKED
         )
         UPDATE ha_outbox_rows r
         SET claim_token = $3, claim_until = now() + ($4::text || ' milliseconds')::interval
         FROM cte
         WHERE r.stream_id = cte.stream_id AND r.source_epoch = cte.source_epoch AND r.sequence = cte.sequence
         RETURNING r.source_epoch, r.sequence, r.fence_token, r.op_digest, r.mutation`,
        [this.streamId, this.batchSize, claimToken, String(this.leaseMs)],
      )).rows;
    });

    let published = 0, acked = 0;
    for (const r of claimed) {
      const sourceEpoch = String(r.source_epoch);
      const sequence = safeSeq(r.sequence, 'row.sequence');
      const storedDigest = String(r.op_digest);
      const mutation = r.mutation as SanitizedMutation<Clean>;
      // (#5) fail closed on a corrupted/tampered stored row.
      this.sanitizer.assertSanitized(mutation);
      const recomputed = canonicalOpDigest<Clean>({ streamId: this.streamId, sourceEpoch, sequence, fenceToken: String(r.fence_token), mutation });
      if (!digestEquals(recomputed, storedDigest)) throw new ContractValidationError(`corrupted outbox row: digest mismatch at ${this.streamId}/${sourceEpoch}/${sequence}`);

      const record: OutboxRecord<unknown> = { contractVersion: '1', streamId: this.streamId, sourceEpoch, sequence, fenceToken: String(r.fence_token), opDigest: storedDigest, mutation };
      // (2) deliver OUTSIDE any tx — no DB lock is held across this network call.
      const receipt = await this.transport.deliverAndAwaitAck(record); // throw → lease expires, retried
      published++;
      // (HIGH2) cryptographically verify the receipt came from the authorized receiver…
      await this.ackVerifier.verify(receipt, record); // throw → not acked
      // …AND is record-bound (echo check on top of the signature).
      if (receipt.streamId !== this.streamId || receipt.sourceEpoch !== sourceEpoch || receipt.sequence !== sequence || !digestEquals(receipt.opDigest, storedDigest)) {
        throw new ContractValidationError('ACK receipt does not match the delivered record — not acking');
      }
      // (3) ACK exactly this row under our claim — short tx, assert 1 row.
      await this.db.transaction(async (exec) => {
        await assertSerializable(exec);
        const res = await exec.query(
          `UPDATE ha_outbox_rows SET published_at = now(), acked_at = now(), claim_token = NULL
           WHERE stream_id = $1 AND source_epoch = $2 AND sequence = $3
             AND acked_at IS NULL AND claim_token = $4 AND op_digest = $5`,
          [this.streamId, sourceEpoch, sequence, claimToken, storedDigest],
        );
        affectedOne(res, 'publisher ack');
      });
      acked++;
    }
    return { published, acked };
  }
}

/**
 * Receiver: one atomic op that locks the RECEIVER checkpoint, validates the
 * record-bound fence token vs the persisted authoritative token, re-asserts
 * sanitization, recomputes the digest, checks idempotency/gap/fork/stale
 * against the durable applied-history, applies the mutation, and advances the
 * independent receiver checkpoint — all in the caller's serializable tx.
 */
export interface MutationApplier<Clean> {
  applyInTx(exec: PgExecutor, record: OutboxRecord<Clean>): Promise<void>;
}
export class PgReceiverCheckpoint<Clean> implements ReceiverCheckpoint<Clean, PgBackend> {
  readonly sanitizer: Pick<MutationSanitizer<unknown, Clean>, 'assertSanitized'>;
  readonly epochAuthorizer: EpochTransitionAuthorizer;
  constructor(
    private readonly streamId: string,
    sanitizer: Pick<MutationSanitizer<unknown, Clean>, 'assertSanitized'>,
    private readonly applier: MutationApplier<Clean>,
    epochAuthorizer: EpochTransitionAuthorizer = { async authorizeTransition() { throw new ContractValidationError('epoch transition not authorized in this slice'); } },
  ) { this.sanitizer = sanitizer; this.epochAuthorizer = epochAuthorizer; }

  async verifyAndApplyInTx(tx: PgTx, record: OutboxRecord<Clean>): Promise<ReceiverDecision> {
    const exec = execOf(tx);
    await assertSerializable(exec);
    if (record.streamId !== this.streamId) throw new ContractValidationError('streamId mismatch for this receiver');
    assertHeaderConformant(record);

    // (5→#1) sanitizer re-check, THEN recompute the digest from the record's own
    // fields + mutation and constant-time compare. A payload changed while the
    // opDigest was preserved is rejected before any classification/apply.
    try { this.sanitizer.assertSanitized(record.mutation); }
    catch { return 'reject-unsanitized'; }
    const recomputed = canonicalOpDigest<Clean>({
      streamId: record.streamId, sourceEpoch: record.sourceEpoch, sequence: record.sequence,
      fenceToken: record.fenceToken, mutation: record.mutation,
    });
    if (!digestEquals(recomputed, record.opDigest)) return 'reject-fork';

    // (#2) record-bound fence vs authoritative persisted token: EXACT equality.
    // A future token is rejected; a missing fence row fails closed.
    const fenceRows = (await exec.query('SELECT fence_token FROM ha_outbox_fence WHERE stream_id = $1 FOR UPDATE', [record.streamId])).rows;
    if (!fenceRows.length) return 'reject-fence';
    if (BigInt(record.fenceToken) !== BigInt(String(fenceRows[0].fence_token))) return 'reject-fence';

    // (HIGH3) receiver's OWN checkpoint authority — not the source allocator's.
    const cpRows = (await exec.query('SELECT source_epoch, sequence FROM ha_outbox_receiver_checkpoint WHERE stream_id = $1 FOR UPDATE', [record.streamId])).rows;
    if (!cpRows.length) throw new ContractValidationError('receiver stream not provisioned');
    const cpEpoch = String(cpRows[0].source_epoch);
    const cpSeq = safeSeq(cpRows[0].sequence, 'receiver.checkpoint.sequence');

    if (record.sourceEpoch !== cpEpoch) return 'reject-epoch';
    if (record.sequence <= cpSeq) {
      // (#3) duplicate/fork decided from the DURABLE receiver applied-history,
      // never the source outbox table (empty on an independent receiver).
      const prior = (await exec.query('SELECT op_digest FROM ha_outbox_applied WHERE stream_id=$1 AND source_epoch=$2 AND sequence=$3', [record.streamId, record.sourceEpoch, record.sequence])).rows;
      if (prior.length && digestEquals(String(prior[0].op_digest), record.opDigest)) return 'duplicate-ok';
      if (prior.length) return 'reject-fork';
      return 'reject-stale';
    }
    if (record.sequence > cpSeq + 1) return 'reject-gap';

    // fresh, in-order → apply + record durable applied-history + advance receiver checkpoint, atomically.
    await this.applier.applyInTx(exec, record);
    const insApplied = await exec.query('INSERT INTO ha_outbox_applied (stream_id, source_epoch, sequence, op_digest) VALUES ($1,$2,$3,$4)', [record.streamId, record.sourceEpoch, record.sequence, record.opDigest]);
    affectedOne(insApplied, 'receiver applied-history insert');
    const updCp = await exec.query('UPDATE ha_outbox_receiver_checkpoint SET sequence=$2, last_digest=$3 WHERE stream_id=$1', [record.streamId, record.sequence, record.opDigest]);
    affectedOne(updCp, 'receiver checkpoint advance');
    return 'applied';
  }

  async transitionEpochInTx(): Promise<'transitioned' | 'duplicate-ok' | 'reject-fork' | 'reject-stale-epoch' | 'reject-fence'> {
    // Epoch transitions remain #16/#15 scope (governed drill); not implemented here.
    throw new ContractValidationError('epoch transition not implemented in this slice (governed transition is separate)');
  }
}

/** Persisted, monotonic promotion fence backed by the fence table. */
export class PgPromotionFence implements PromotionFence {
  constructor(private readonly db: PgTransactor) {}
  async acquire(streamId: string): Promise<FenceToken> {
    return this.db.transaction(async (exec) => {
      await assertSerializable(exec);
      const res = await exec.query(
        `INSERT INTO ha_outbox_fence (stream_id, fence_token) VALUES ($1, 1)
         ON CONFLICT (stream_id) DO UPDATE SET fence_token = ha_outbox_fence.fence_token + 1
         RETURNING fence_token`, [streamId]);
      affectedOne(res, 'promotion fence acquire');
      return BigInt(String(res.rows[0].fence_token));
    });
  }
  async current(streamId: string): Promise<FenceToken> {
    const rows = (await this.db.transaction((exec) => exec.query('SELECT fence_token FROM ha_outbox_fence WHERE stream_id = $1', [streamId]))).rows;
    return rows.length ? BigInt(String(rows[0].fence_token)) : 0n;
  }
}
