import { ContractValidationError } from './ha-outbox-contract.js';
import type { PgExecutor, PgTransactor } from './ha-outbox-pg.js';

export interface NodePostgresResult {
  rows: Record<string, unknown>[];
  rowCount: number | null;
  command?: string;
}

export interface NodePostgresClient {
  query(sql: string, params?: unknown[]): Promise<NodePostgresResult>;
  release(destroy?: boolean | Error): void;
}

export interface NodePostgresPool {
  connect(): Promise<NodePostgresClient>;
}

export interface NodePostgresTransactorOptions {
  statementTimeoutMs?: number;
  transactionTimeoutMs?: number;
  acquireTimeoutMs?: number;
  rollbackTimeoutMs?: number;
  maxSerializationRetries?: number;
  retryBaseDelayMs?: number;
  onDisposalError?: (error: unknown, phase: 'active' | 'late-acquire') => void | Promise<void>;
}

export class PostCommitReleaseError extends Error {
  readonly committed = true;
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'PostCommitReleaseError';
  }
}

export class AmbiguousCommitError extends Error {
  readonly committed = 'unknown' as const;
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'AmbiguousCommitError';
  }
}

export class ConnectionDisposalError extends Error {
  readonly committed = false;
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'ConnectionDisposalError';
  }
}

const MAX_TIMER_MS = 2_147_483_647;
const RETRYABLE = new Set(['40001', '40P01']);

function boundedInteger(value: number, label: string, min = 1, max = MAX_TIMER_MS): number {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new ContractValidationError(`${label} must be a safe integer in [${min}, ${max}]`);
  }
  return value;
}

function abortError(signal: AbortSignal): Error {
  return signal.reason instanceof Error
    ? signal.reason
    : new ContractValidationError('PostgreSQL transaction aborted');
}

function abortRace<T>(work: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) return Promise.reject(abortError(signal));
  let onAbort!: () => void;
  const aborted = new Promise<never>((_, reject) => {
    onAbort = () => reject(abortError(signal));
    signal.addEventListener('abort', onAbort, { once: true });
  });
  work.catch(() => {});
  return Promise.race([work, aborted]).finally(() => signal.removeEventListener('abort', onAbort));
}

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) return reject(abortError(signal));
    const onAbort = () => {
      clearTimeout(timer);
      signal.removeEventListener('abort', onAbort);
      reject(abortError(signal));
    };
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    signal.addEventListener('abort', onAbort, { once: true });
  });
}

async function boundedRollback(client: NodePostgresClient, ms: number): Promise<void> {
  let timer!: ReturnType<typeof setTimeout>;
  const timeout = new Promise<void>((resolve) => { timer = setTimeout(resolve, ms); });
  try {
    await Promise.race([client.query('ROLLBACK').then(() => undefined).catch(() => undefined), timeout]);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Production node-postgres adapter for the durable-outbox PgTransactor contract.
 * The total deadline covers acquisition, BEGIN, timeout setup, work, and COMMIT.
 * On any timeout/abort/error the checked-out connection is destroyed, never reused.
 * Serialization/deadlock retries are bounded and disabled by default because a
 * transaction callback can contain caller-side effects that cannot be replayed.
 */
export class NodePostgresTransactor implements PgTransactor {
  private readonly statementTimeoutMs: number;
  private readonly transactionTimeoutMs: number;
  private readonly acquireTimeoutMs: number;
  private readonly rollbackTimeoutMs: number;
  private readonly maxSerializationRetries: number;
  private readonly retryBaseDelayMs: number;
  private readonly onDisposalError?: NodePostgresTransactorOptions['onDisposalError'];

  constructor(private readonly pool: NodePostgresPool, opts: NodePostgresTransactorOptions = {}) {
    if (!pool || typeof pool.connect !== 'function') {
      throw new ContractValidationError('pool.connect is required');
    }
    this.statementTimeoutMs = boundedInteger(opts.statementTimeoutMs ?? 30_000, 'statementTimeoutMs');
    this.transactionTimeoutMs = boundedInteger(opts.transactionTimeoutMs ?? 35_000, 'transactionTimeoutMs');
    this.acquireTimeoutMs = boundedInteger(opts.acquireTimeoutMs ?? 5_000, 'acquireTimeoutMs');
    this.rollbackTimeoutMs = boundedInteger(opts.rollbackTimeoutMs ?? 1_000, 'rollbackTimeoutMs');
    this.maxSerializationRetries = boundedInteger(opts.maxSerializationRetries ?? 0, 'maxSerializationRetries', 0, 100);
    this.retryBaseDelayMs = boundedInteger(opts.retryBaseDelayMs ?? 10, 'retryBaseDelayMs', 1, 1_000);
    if (opts.onDisposalError !== undefined && typeof opts.onDisposalError !== 'function') {
      throw new ContractValidationError('onDisposalError must be a function');
    }
    this.onDisposalError = opts.onDisposalError;
  }

  async transaction<T>(fn: (exec: PgExecutor) => Promise<T>, opts?: { signal?: AbortSignal }): Promise<T> {
    const controller = new AbortController();
    const caller = opts?.signal;
    const onCallerAbort = () => controller.abort(abortError(caller!));
    if (caller?.aborted) controller.abort(abortError(caller));
    else caller?.addEventListener('abort', onCallerAbort, { once: true });
    const timer = setTimeout(
      () => controller.abort(new ContractValidationError(
        `PostgreSQL transaction deadline exceeded (${this.transactionTimeoutMs}ms)`,
      )),
      this.transactionTimeoutMs,
    );
    try {
      for (let attempt = 0; ; attempt++) {
        if (controller.signal.aborted) throw abortError(controller.signal);
        try {
          return await this.runOnce(fn, controller.signal);
        } catch (error) {
          const code = (error as { code?: unknown })?.code;
          if (
            typeof code !== 'string'
            || !RETRYABLE.has(code)
            || attempt >= this.maxSerializationRetries
            || controller.signal.aborted
          ) throw error;
          await sleep(Math.min(this.retryBaseDelayMs * (2 ** attempt), 1_000), controller.signal);
        }
      }
    } finally {
      clearTimeout(timer);
      caller?.removeEventListener('abort', onCallerAbort);
    }
  }

  private reportDisposalError(error: unknown, phase: 'active' | 'late-acquire'): void {
    try {
      const observed = this.onDisposalError?.(error, phase);
      if (observed && typeof observed.then === 'function') observed.catch(() => {});
    } catch { /* telemetry cannot change the transaction outcome */ }
  }

  private async acquire(signal: AbortSignal): Promise<NodePostgresClient> {
    const pending = this.pool.connect();
    let timer!: ReturnType<typeof setTimeout>;
    let onAbort!: () => void;
    const gate = new Promise<never>((_, reject) => {
      timer = setTimeout(
        () => reject(new ContractValidationError('PostgreSQL connection acquisition timed out')),
        this.acquireTimeoutMs,
      );
      onAbort = () => reject(abortError(signal));
      signal.addEventListener('abort', onAbort, { once: true });
    });
    try {
      return await Promise.race([pending, gate]);
    } catch (error) {
      pending.then((late) => {
        try { late.release(true); } catch (releaseError) {
          this.reportDisposalError(releaseError, 'late-acquire');
        }
      }).catch(() => {});
      throw error;
    } finally {
      clearTimeout(timer);
      signal.removeEventListener('abort', onAbort);
    }
  }

  private async runOnce<T>(fn: (exec: PgExecutor) => Promise<T>, signal: AbortSignal): Promise<T> {
    const client = await this.acquire(signal);
    let releaseState: 'open' | 'released' | 'destroyed' | 'failed' = 'open';
    let disposalError: unknown;
    let committed = false;
    let commitDispatched = false;
    let commitDefinitivelyAborted = false;
    const terminalRelease = (destroy: boolean) => {
      if (releaseState !== 'open') return;
      releaseState = destroy ? 'destroyed' : 'released';
      try {
        client.release(destroy);
      } catch (error) {
        releaseState = 'failed';
        disposalError = error;
        this.reportDisposalError(error, 'active');
      }
    };
    const destroy = () => {
      terminalRelease(true);
    };
    const releaseNormally = () => {
      terminalRelease(false);
      if (releaseState === 'failed') {
        throw new PostCommitReleaseError(
          'PostgreSQL committed but returning the connection to the pool failed',
          { cause: disposalError },
        );
      }
    };
    const onAbort = () => destroy();
    signal.addEventListener('abort', onAbort, { once: true });

    const query = (sql: string, params?: unknown[]) => {
      if (signal.aborted) return Promise.reject(abortError(signal));
      return abortRace(client.query(sql, params), signal);
    };
    try {
      const begin = await query('BEGIN ISOLATION LEVEL SERIALIZABLE');
      if (begin.command !== 'BEGIN') {
        throw new ContractValidationError(`PostgreSQL BEGIN was not confirmed (command=${begin.command ?? 'missing'})`);
      }
      const timeout = await query("SELECT set_config('statement_timeout', $1, true) AS statement_timeout", [String(this.statementTimeoutMs)]);
      if (timeout.command !== 'SELECT' || typeof timeout.rows[0]?.statement_timeout !== 'string') {
        throw new ContractValidationError('PostgreSQL statement_timeout setup was not confirmed');
      }
      const timeoutCheck = await query(
        "SELECT (EXTRACT(EPOCH FROM current_setting('statement_timeout')::interval) * 1000)::bigint::text AS statement_timeout_ms",
      );
      if (timeoutCheck.command !== 'SELECT' || timeoutCheck.rows[0]?.statement_timeout_ms !== String(this.statementTimeoutMs)) {
        throw new ContractValidationError('PostgreSQL statement_timeout setup was not confirmed');
      }
      const exec: PgExecutor = {
        query: async (sql, params) => {
          const result = await query(sql, params);
          return { rows: result.rows, rowCount: result.rowCount ?? 0 };
        },
      };
      const result = await abortRace(fn(exec), signal);
      commitDispatched = true;
      const commit = await query('COMMIT');
      if (commit.command !== 'COMMIT') {
        commitDefinitivelyAborted = commit.command === 'ROLLBACK';
        throw new ContractValidationError(`PostgreSQL COMMIT was not confirmed (command=${commit.command ?? 'missing'})`);
      }
      committed = true;
      releaseNormally();
      return result;
    } catch (error) {
      if (!committed && !commitDispatched && releaseState === 'open') {
        await boundedRollback(client, this.rollbackTimeoutMs);
      }
      if (releaseState === 'open') destroy();
      if (commitDispatched && !committed && !commitDefinitivelyAborted) {
        const cause = disposalError === undefined
          ? error
          : new AggregateError([error, disposalError], 'commit response and connection disposal both failed');
        throw new AmbiguousCommitError(
          'PostgreSQL COMMIT was dispatched but its outcome could not be confirmed; reconcile by idempotency key before retry',
          { cause },
        );
      }
      if (!committed && disposalError !== undefined) {
        throw new ConnectionDisposalError(
          'PostgreSQL transaction failed and the connection could not be disposed',
          { cause: new AggregateError([error, disposalError]) },
        );
      }
      throw error;
    } finally {
      signal.removeEventListener('abort', onAbort);
      if (releaseState === 'open') destroy();
    }
  }
}
