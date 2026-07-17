/**
 * PostgreSQL implementation of the HA durable-outbox contract (#16).
 *
 * Provides a transactionally-coupled authoritative mutation + outbox append with
 * in-tx sequence allocation and fence validation, a durable publisher that
 * records ACK state and never sheds, and a receiver that verifies+applies+
 * checkpoints idempotently under one lock. Conforms to `ha-outbox-contract.ts`.
 *
 * BOUNDARY: this is the single-authority implementation + adversarial integration
 * tests. It makes NO crash-durable-HA claim on its own — issue #16 stays OPEN
 * until the real two-node PostgreSQL(+Redis) failover/split-brain drill passes
 * with recorded RPO/RTO. No release-claim expansion.
 */
import { timingSafeEqual } from 'node:crypto';
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

/** A transaction-scoped executor (all queries run inside one DB transaction). */
export interface PgExecutor {
  query(sql: string, params?: unknown[]): Promise<{ rows: Record<string, unknown>[] }>;
}

/** Runs `fn` inside a single serializable DB transaction: BEGIN, run, COMMIT;
 *  ROLLBACK (and rethrow) on any throw. */
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
 *  throw — never silently truncate an unsafe bigint via Number(). */
function safeSeq(v: unknown, label: string): number {
  const b = BigInt(String(v));
  if (b < 0n || b > BigInt(Number.MAX_SAFE_INTEGER)) throw new ContractValidationError(`${label} out of safe-integer range`);
  return Number(b);
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

/** DDL for the outbox/checkpoint/fence tables (one stream namespace per row-set). */
export const HA_OUTBOX_PG_SCHEMA = `
CREATE TABLE IF NOT EXISTS ha_outbox_fence (
  stream_id     text PRIMARY KEY,
  fence_token   numeric NOT NULL DEFAULT 0        -- authoritative monotonic token
);
CREATE TABLE IF NOT EXISTS ha_outbox_checkpoint (
  stream_id     text PRIMARY KEY,
  source_epoch  text NOT NULL,
  epoch_index   bigint NOT NULL DEFAULT 0,
  sequence      bigint NOT NULL DEFAULT 0,        -- last applied (receiver) / allocated (source)
  last_digest   text NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS ha_outbox_rows (
  stream_id     text NOT NULL,
  source_epoch  text NOT NULL,
  sequence      bigint NOT NULL,
  fence_token   numeric NOT NULL,
  op_digest     text NOT NULL,
  mutation      jsonb NOT NULL,                   -- secret-stripped
  published_at  timestamptz,
  acked_at      timestamptz,
  PRIMARY KEY (stream_id, source_epoch, sequence)
);
CREATE INDEX IF NOT EXISTS ha_outbox_rows_unacked
  ON ha_outbox_rows (stream_id, sequence) WHERE acked_at IS NULL;
-- Receiver-side durable applied history (independent of the source outbox
-- table) so duplicate/fork/stale decisions survive on the receiver.
CREATE TABLE IF NOT EXISTS ha_outbox_applied (
  stream_id     text NOT NULL,
  source_epoch  text NOT NULL,
  sequence      bigint NOT NULL,
  op_digest     text NOT NULL,
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
 * The source-side durable outbox. `withOutboxTx` opens ONE DB transaction and
 * yields a bound `DurableTx`; `appendInTx` runs entirely inside it: fence check,
 * admission (bounded), sequence allocation, sanitize, digest, and row insert all
 * commit or roll back together with the caller's authoritative mutation.
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
    return this.db.transaction(async (exec) => fn(createBoundTx(exec), exec));
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
    const pending = Number((await exec.query('SELECT count(*)::int AS n FROM ha_outbox_rows WHERE stream_id = $1 AND acked_at IS NULL', [streamId])).rows[0].n);
    if (pending >= this.opts.maxPendingRows) throw new OutboxBackpressureError(this.opts.backpressure);

    // (i) allocate the next sequence within the tx (checkpoint row is the allocator).
    const cpRows = (await exec.query('SELECT source_epoch, sequence FROM ha_outbox_checkpoint WHERE stream_id = $1 FOR UPDATE', [streamId])).rows;
    if (!cpRows.length) throw new ContractValidationError('stream not provisioned (no checkpoint row)');
    const sourceEpoch = String(cpRows[0].source_epoch);
    const nextSeq = Number(cpRows[0].sequence) + 1;

    // (10) sanitize the RAW mutation here (runtime binding); digest the sanitized form.
    const mutation = this.sanitizer.sanitize(input.rawMutation);
    const opDigest = canonicalOpDigest<Clean>({ streamId, sourceEpoch, sequence: nextSeq, fenceToken: fenceDecimal, mutation });

    await exec.query(
      'INSERT INTO ha_outbox_rows (stream_id, source_epoch, sequence, fence_token, op_digest, mutation) VALUES ($1,$2,$3,$4,$5,$6)',
      [streamId, sourceEpoch, nextSeq, fenceDecimal, opDigest, JSON.stringify(mutation)],
    );
    await exec.query('UPDATE ha_outbox_checkpoint SET sequence = $2 WHERE stream_id = $1', [streamId, nextSeq]);

    const header: OutboxRecordHeader = { contractVersion: '1', streamId, sourceEpoch, sequence: nextSeq, fenceToken: fenceDecimal, opDigest };
    assertHeaderConformant(header);
    return header;
  }
}

/**
 * Durable publisher: drains committed, unacked rows in order, hands each to the
 * injected transport, and records the ACK durably. Never sheds; a transport
 * failure leaves the row unacked for retry.
 */
/** (#4) Record-bound acknowledgement the receiver returns to prove it durably
 *  applied (or idempotently accepted) THIS exact record. */
export interface AckReceipt {
  streamId: string;
  sourceEpoch: string;
  sequence: number;
  opDigest: string;
}
/** Transport delivers a record and returns the receiver's durable ACK receipt.
 *  A throw (or a receipt that does not match) leaves the row unacked (at-least-
 *  once retry) — the row is NEVER acked on call-completion alone. */
export interface OutboxTransport {
  deliverAndAwaitAck(record: OutboxRecord<unknown>): Promise<AckReceipt>;
}
export class PgDurablePublisher<Clean> {
  constructor(
    private readonly db: PgTransactor,
    private readonly streamId: string,
    private readonly transport: OutboxTransport,
    readonly backpressure: PublisherBackpressure,
    /** (#5) sanitizer to revalidate each DB row before publishing. */
    private readonly sanitizer: Pick<MutationSanitizer<unknown, Clean>, 'assertSanitized'>,
  ) {}

  async drainOnce(): Promise<{ published: number; acked: number }> {
    return this.db.transaction(async (exec) => {
      const rows = (await exec.query(
        'SELECT source_epoch, sequence, fence_token, op_digest, mutation FROM ha_outbox_rows WHERE stream_id = $1 AND acked_at IS NULL ORDER BY sequence ASC FOR UPDATE SKIP LOCKED',
        [this.streamId],
      )).rows;
      let published = 0, acked = 0;
      for (const r of rows) {
        const sourceEpoch = String(r.source_epoch);
        const sequence = safeSeq(r.sequence, 'row.sequence');
        const storedDigest = String(r.op_digest);
        const mutation = r.mutation as SanitizedMutation<Clean>;
        // (#5) fail closed on a corrupted/tampered stored row: revalidate the
        // sanitizer AND recompute the digest before publishing.
        this.sanitizer.assertSanitized(mutation);
        const recomputed = canonicalOpDigest<Clean>({ streamId: this.streamId, sourceEpoch, sequence, fenceToken: String(r.fence_token), mutation });
        if (!digestEquals(recomputed, storedDigest)) throw new ContractValidationError(`corrupted outbox row: digest mismatch at ${this.streamId}/${sourceEpoch}/${sequence}`);

        const record: OutboxRecord<unknown> = { contractVersion: '1', streamId: this.streamId, sourceEpoch, sequence, fenceToken: String(r.fence_token), opDigest: storedDigest, mutation };
        const receipt = await this.transport.deliverAndAwaitAck(record); // throw → row stays unacked (retry)
        published++;
        // (#4) only ACK when the receipt is record-bound and matches exactly.
        if (receipt.streamId !== this.streamId || receipt.sourceEpoch !== sourceEpoch || receipt.sequence !== sequence || !digestEquals(receipt.opDigest, storedDigest)) {
          throw new ContractValidationError('ACK receipt does not match the delivered record — not acking');
        }
        await exec.query('UPDATE ha_outbox_rows SET published_at = now(), acked_at = now() WHERE stream_id=$1 AND source_epoch=$2 AND sequence=$3', [this.streamId, sourceEpoch, sequence]);
        acked++;
      }
      return { published, acked };
    });
  }
}

/**
 * Receiver: one atomic op that locks the checkpoint, validates the record-bound
 * fence token vs the persisted authoritative token, re-asserts sanitization,
 * checks idempotency/gap/fork/stale, applies the mutation, and advances the
 * durable checkpoint — all in the caller's tx.
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

    const cpRows = (await exec.query('SELECT source_epoch, sequence FROM ha_outbox_checkpoint WHERE stream_id = $1 FOR UPDATE', [record.streamId])).rows;
    if (!cpRows.length) throw new ContractValidationError('receiver stream not provisioned');
    const cpEpoch = String(cpRows[0].source_epoch);
    const cpSeq = safeSeq(cpRows[0].sequence, 'checkpoint.sequence');

    if (record.sourceEpoch !== cpEpoch) return 'reject-epoch';
    if (record.sequence <= cpSeq) {
      // (#3) duplicate/fork decided from the DURABLE receiver-applied history,
      // never the source outbox table (empty on an independent receiver).
      const prior = (await exec.query('SELECT op_digest FROM ha_outbox_applied WHERE stream_id=$1 AND source_epoch=$2 AND sequence=$3', [record.streamId, record.sourceEpoch, record.sequence])).rows;
      if (prior.length && digestEquals(String(prior[0].op_digest), record.opDigest)) return 'duplicate-ok';
      if (prior.length) return 'reject-fork';
      return 'reject-stale';
    }
    if (record.sequence > cpSeq + 1) return 'reject-gap';

    // fresh, in-order → apply + record durable applied-history + advance checkpoint, atomically.
    await this.applier.applyInTx(exec, record);
    await exec.query('INSERT INTO ha_outbox_applied (stream_id, source_epoch, sequence, op_digest) VALUES ($1,$2,$3,$4)', [record.streamId, record.sourceEpoch, record.sequence, record.opDigest]);
    await exec.query('UPDATE ha_outbox_checkpoint SET sequence=$2, last_digest=$3 WHERE stream_id=$1', [record.streamId, record.sequence, record.opDigest]);
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
      const rows = (await exec.query(
        `INSERT INTO ha_outbox_fence (stream_id, fence_token) VALUES ($1, 1)
         ON CONFLICT (stream_id) DO UPDATE SET fence_token = ha_outbox_fence.fence_token + 1
         RETURNING fence_token`, [streamId])).rows;
      return BigInt(String(rows[0].fence_token));
    });
  }
  async current(streamId: string): Promise<FenceToken> {
    const rows = (await this.db.transaction((exec) => exec.query('SELECT fence_token FROM ha_outbox_fence WHERE stream_id = $1', [streamId]))).rows;
    return rows.length ? BigInt(String(rows[0].fence_token)) : 0n;
  }
}
