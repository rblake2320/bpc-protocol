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
    const persistedFence = fenceRows.length ? BigInt(String(fenceRows[0].fence_token)) : 0n;
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
export interface OutboxTransport {
  deliver(record: OutboxRecord<unknown>): Promise<void>;
}
export class PgDurablePublisher {
  constructor(
    private readonly db: PgTransactor,
    private readonly streamId: string,
    private readonly transport: OutboxTransport,
    readonly backpressure: PublisherBackpressure,
  ) {}

  async drainOnce(): Promise<{ published: number; acked: number }> {
    return this.db.transaction(async (exec) => {
      const rows = (await exec.query(
        'SELECT source_epoch, sequence, fence_token, op_digest, mutation FROM ha_outbox_rows WHERE stream_id = $1 AND acked_at IS NULL ORDER BY sequence ASC FOR UPDATE SKIP LOCKED',
        [this.streamId],
      )).rows;
      let published = 0, acked = 0;
      for (const r of rows) {
        const record: OutboxRecord<unknown> = {
          contractVersion: '1', streamId: this.streamId, sourceEpoch: String(r.source_epoch),
          sequence: Number(r.sequence), fenceToken: String(r.fence_token), opDigest: String(r.op_digest),
          mutation: r.mutation as SanitizedMutation<unknown>,
        };
        await this.transport.deliver(record); // throw → row stays unacked (retry), never dropped
        published++;
        await exec.query('UPDATE ha_outbox_rows SET published_at = now(), acked_at = now() WHERE stream_id=$1 AND source_epoch=$2 AND sequence=$3', [this.streamId, record.sourceEpoch, record.sequence]);
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

    // record-bound fence vs authoritative persisted token (locked).
    const fenceRows = (await exec.query('SELECT fence_token FROM ha_outbox_fence WHERE stream_id = $1 FOR UPDATE', [record.streamId])).rows;
    const persistedFence = fenceRows.length ? BigInt(String(fenceRows[0].fence_token)) : 0n;
    if (BigInt(record.fenceToken) < persistedFence) return 'reject-fence';

    // sanitizer re-check on the receiver.
    try { this.sanitizer.assertSanitized(record.mutation); }
    catch { return 'reject-unsanitized'; }

    const cpRows = (await exec.query('SELECT source_epoch, sequence, last_digest FROM ha_outbox_checkpoint WHERE stream_id = $1 FOR UPDATE', [record.streamId])).rows;
    if (!cpRows.length) throw new ContractValidationError('receiver stream not provisioned');
    const cpEpoch = String(cpRows[0].source_epoch);
    const cpSeq = Number(cpRows[0].sequence);
    const cpLastDigest = String(cpRows[0].last_digest);

    if (record.sourceEpoch !== cpEpoch) return 'reject-epoch';
    if (record.sequence <= cpSeq) {
      // (c) duplicate: same key AND identical digest at that position → idempotent.
      if (record.sequence === cpSeq && record.opDigest === cpLastDigest) return 'duplicate-ok';
      const dupe = (await exec.query('SELECT op_digest FROM ha_outbox_rows WHERE stream_id=$1 AND source_epoch=$2 AND sequence=$3', [record.streamId, record.sourceEpoch, record.sequence])).rows;
      if (dupe.length && String(dupe[0].op_digest) === record.opDigest) return 'duplicate-ok';
      if (dupe.length && String(dupe[0].op_digest) !== record.opDigest) return 'reject-fork';
      return 'reject-stale';
    }
    if (record.sequence > cpSeq + 1) return 'reject-gap';

    // fresh, in-order → apply + advance checkpoint atomically.
    await this.applier.applyInTx(exec, record);
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
