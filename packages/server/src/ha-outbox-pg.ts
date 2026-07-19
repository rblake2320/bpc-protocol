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
 * by the real-PostgreSQL integration (ha-outbox-pg-integration.mts, run in CI
 * via `npm run test:postgres:ha`, which THROWS if BPC_TEST_POSTGRES_URL is unset
 * so it cannot silently skip). Issue #16 stays OPEN until the two-node
 * PostgreSQL(+Redis) failover/split-brain drill passes with recorded RPO/RTO.
 *
 * STARTUP CONTRACT: callers obtain a `SchemaReadyToken` from
 * `assertSchemaReady(db, schema)` (or provision/adopt) — a full manifest
 * attestation + version check in the pinned schema, minting an UNFORGEABLE
 * capability bound to that exact transactor + schema. Every mechanism constructor
 * REQUIRES the token, so an object cannot be built (and cannot operate) without a
 * verified, identity-bound readiness proof; there is no direct unsafe
 * construction. The receiver OWNS its transactor (verifyAndApplyDelivered), and a
 * bound tx carries its transactor+schema identity, so a token/tx for one database
 * can never be used to apply against another. PRIVILEGE SEPARATION: the token
 * proves STARTUP state; the runtime identity MUST NOT hold DDL rights, else the
 * attested structure could be mutated under it. #16 stays OPEN.
 */
import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
import { types as utilTypes } from 'node:util';
import {
  ContractValidationError,
  OutboxBackpressureError,
  StaleFenceError,
  assertHeaderConformant,
  canonicalize,
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

function deepFreezeJson<T>(value: T): T {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value as Record<string, unknown>)) deepFreezeJson(child);
    Object.freeze(value);
  }
  return value;
}

function assertNoProxyGraph(value: unknown, seen = new WeakSet<object>()): void {
  if (value === null || typeof value !== 'object') return;
  if (utilTypes.isProxy(value)) throw new ContractValidationError('proxy objects are not accepted at an asynchronous trust boundary');
  if (seen.has(value)) throw new ContractValidationError('cyclic objects are not canonicalizable');
  seen.add(value);
  for (const descriptor of Object.values(Object.getOwnPropertyDescriptors(value))) {
    if ('value' in descriptor) assertNoProxyGraph(descriptor.value, seen);
  }
  seen.delete(value);
}

/** Canonicalization rejects prototypes, accessors, symbols, sparse arrays and
 * non-I-JSON values before any asynchronous boundary. Parsing creates a detached
 * plain-data graph; freezing prevents a collaborator from changing the verified
 * bytes while an injected signer, transport, verifier or applier is awaited. */
function snapshotJson<T>(value: T, label: string): T {
  try {
    assertNoProxyGraph(value);
    return deepFreezeJson(JSON.parse(canonicalize(value)) as T);
  } catch (error) {
    if (error instanceof ContractValidationError) throw error;
    throw new ContractValidationError(`${label} is not canonical I-JSON`);
  }
}

function assertExactOwnKeys(value: object, expected: readonly string[], label: string): void {
  if (Object.getOwnPropertySymbols(value).length) throw new ContractValidationError(`${label} has symbol fields`);
  const actual = Object.getOwnPropertyNames(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new ContractValidationError(`${label} has unexpected or missing fields`);
  }
  for (const key of actual) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key)!;
    if (!('value' in descriptor) || !descriptor.enumerable) throw new ContractValidationError(`${label} field '${key}' must be an enumerable data property`);
  }
}

function snapshotRecord<Clean>(record: OutboxRecord<Clean>): OutboxRecord<Clean> {
  const snapshot = snapshotJson(record, 'outbox record');
  assertExactOwnKeys(snapshot as object, ['contractVersion', 'streamId', 'sourceEpoch', 'sequence', 'fenceToken', 'opDigest', 'mutation'], 'outbox record');
  assertHeaderConformant(snapshot);
  return snapshot;
}

function snapshotAppendInput<Raw>(input: { streamId: string; rawMutation: Raw; fenceToken: FenceToken }): {
  streamId: string; rawMutation: Raw; fenceToken: FenceToken;
} {
  if (utilTypes.isProxy(input)) throw new ContractValidationError('append input cannot be a proxy');
  if (input === null || typeof input !== 'object' || (Object.getPrototypeOf(input) !== Object.prototype && Object.getPrototypeOf(input) !== null)) {
    throw new ContractValidationError('append input must be a plain object');
  }
  if (Object.getOwnPropertySymbols(input).length) throw new ContractValidationError('append input cannot contain symbol fields');
  assertExactOwnKeys(input, ['streamId', 'rawMutation', 'fenceToken'], 'append input');
  for (const key of ['streamId', 'rawMutation', 'fenceToken'] as const) {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (!descriptor || !('value' in descriptor) || !descriptor.enumerable) throw new ContractValidationError(`append input field '${key}' must be an enumerable data property`);
  }
  const streamId = Object.getOwnPropertyDescriptor(input, 'streamId')!.value as unknown;
  const rawMutation = Object.getOwnPropertyDescriptor(input, 'rawMutation')!.value as Raw;
  const fenceToken = Object.getOwnPropertyDescriptor(input, 'fenceToken')!.value as unknown;
  if (typeof streamId !== 'string' || typeof fenceToken !== 'bigint') throw new ContractValidationError('append input has invalid streamId or fenceToken');
  return Object.freeze({ streamId, rawMutation: snapshotJson(rawMutation, 'raw mutation'), fenceToken });
}

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

/**
 * Runs `fn` inside a single SERIALIZABLE DB transaction: BEGIN ISOLATION LEVEL
 * SERIALIZABLE, run, COMMIT; ROLLBACK (and rethrow) on any throw. Serializable is
 * not merely a comment — every critical tx re-asserts it at runtime.
 *
 * (R12) A conforming transactor MUST, for assurance-grade availability + integrity:
 *  - bound every query at the CONNECTION layer (e.g. statement_timeout + a socket
 *    timeout) so a network-hung query cannot block indefinitely — the scope
 *    deadline here is a mechanism-layer backstop, not a substitute;
 *  - VERIFY that COMMIT actually committed (the command tag is `COMMIT`, not
 *    `ROLLBACK` — an aborted tx turns COMMIT into a silent rollback) and surface a
 *    failure if it did not;
 *  - DISCARD (not reuse/return to the pool) any connection whose tx errored, timed
 *    out, or failed to commit, so a poisoned/hung connection is never reused;
 *  - HONOR `opts.signal`: on abort, CANCEL the in-flight query (e.g. a PostgreSQL
 *    CancelRequest) and DESTROY the connection promptly WITHOUT unbounded-awaiting
 *    ROLLBACK — the server aborts the tx when the connection drops.
 */
export interface PgTransactor {
  transaction<T>(fn: (exec: PgExecutor) => Promise<T>, opts?: { signal?: AbortSignal }): Promise<T>;
  /**
   * Optional migration-only entry point. The adapter must acquire the listed
   * ACCESS EXCLUSIVE locks before any statement establishes the SERIALIZABLE
   * snapshot. Callers fail closed when the adapter cannot provide this order.
   */
  transactionWithInitialExclusiveLocks?<T>(
    relations: readonly { schema: string; table: string }[],
    fn: (exec: PgExecutor) => Promise<T>,
    opts?: { signal?: AbortSignal },
  ): Promise<T>;
}

// The opaque DurableTx carries no public members; its executor AND the identity
// of the transactor+schema that produced it are held in a module-private WeakMap.
// A bound tx can therefore only be minted from inside a transactor-owning method
// (the class calls `this.db.transaction`, so the recorded `db` is the REAL one
// that produced the executor). There is no public minter, so a caller cannot wrap
// a foreign executor and feed it to another object bound to a different db.
interface BoundTxState { db: PgTransactor; schema: string; scoped: PgExecutor }
const TX_STATE = new WeakMap<object, BoundTxState>();

function boundStateOf(tx: PgTx): BoundTxState {
  const st = TX_STATE.get(tx as unknown as object);
  if (!st) throw new ContractValidationError('DurableTx not bound to a PostgreSQL transaction (forged, foreign, or used after its scope)');
  return st;
}

/** (R9/R10/R11/HIGH) Return a CAPABILITY-SCOPED executor of a bound tx, ONLY if
 *  that tx was produced by THIS object's exact transactor + schema. The returned
 *  executor is a proxy that RE-CHECKS the tx is still active on EVERY query — so
 *  a capability captured once cannot drive a later query after the tx scope ends
 *  (the async-retention bypass). Callers never receive the raw executor. */
function execOfBound(tx: PgTx, db: PgTransactor, schema: string): PgExecutor {
  const st = boundStateOf(tx);
  if (st.db !== db) throw new ContractValidationError('DurableTx is bound to a different transactor than this object');
  if (st.schema !== schema) throw new ContractValidationError('DurableTx is bound to a different schema than this object');
  return st.scoped;
}

/** Default upper bound on a single transaction scope. */
const DEFAULT_SCOPE_DEADLINE_MS = 30_000;
/** setTimeout clamps delays above this (~24.8 days) to ~1ms, silently defeating a
 *  deadline; reject any value outside a finite 1..2^31-1 ms integer. */
const MAX_TIMER_MS = 2_147_483_647;

function validateDeadlineMs(ms: number, label: string): number {
  if (!Number.isInteger(ms) || ms < 1 || ms > MAX_TIMER_MS) {
    throw new ContractValidationError(`${label} must be an integer in [1, ${MAX_TIMER_MS}] ms`);
  }
  return ms;
}

/**
 * (R12/R13) Run `run(signal)` under a bounded scope deadline. On timeout the
 * AbortController is aborted — so a conforming `PgTransactor` (which receives the
 * signal) can CANCEL the in-flight query and DESTROY the connection — AND the
 * returned promise rejects promptly (the mechanism layer never awaits a hung
 * connection). The timer is always cleared.
 *
 * BOUNDARY: this bounds the MECHANISM's await and signals abort. End-to-end
 * availability under a network-hung connection depends on the transactor honoring
 * the signal (cancel + destroy). This slice ships the contract + signal, not a
 * production driver, so availability under partition remains an OPEN item (with
 * #16), not a closed guarantee.
 */
function runScoped<T>(ms: number, run: (signal: AbortSignal) => Promise<T>): Promise<T> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout>;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      const err = new ContractValidationError(`transaction scope deadline exceeded (${ms}ms) — aborting; the transactor must cancel the in-flight query and discard this connection`);
      controller.abort(err);
      reject(err);
    }, ms);
  });
  const p = run(controller.signal);
  p.catch(() => {}); // if the deadline wins the race, swallow p's late settlement
  return Promise.race([p, deadline]).finally(() => clearTimeout(timer));
}

/**
 * (R10/R11/R12/HIGH) Run `body` with a bound `DurableTx` under a STRUCTURED,
 * DEADLINE-BOUNDED capability scope. Callers never receive the raw executor —
 * only a proxy that rejects any query once the scope is closing or the tx is
 * revoked (no LATER query after scope end).
 *
 * Integrity (R12): every launched query's settlement is RETAINED (never removed
 * on settle), so a fast unawaited REJECTION cannot vanish before the scope
 * observes it — any launched-query rejection, or any query still pending at
 * close, fails the scope and forces the surrounding db.transaction to ROLL BACK.
 *
 * Availability (R12): the whole scope (body + drain of launched queries) races a
 * bounded deadline. A never-resolving / network-hung query causes the deadline
 * to fire and the scope to reject (rollback) rather than pin the tx+connection
 * forever. The transactor MUST then discard that connection (see PgTransactor).
 * The tx handle is revoked in `finally` regardless.
 */
async function withBoundTx<T>(
  exec: PgExecutor,
  db: PgTransactor,
  schema: string,
  body: (tx: PgTx, scoped: PgExecutor) => Promise<T>,
): Promise<T> {
  const tx = Object.freeze({}) as unknown as PgTx;
  let closing = false;
  let rejectionSeen = false;
  let firstRejection: unknown;
  let pending = 0;
  const settlements: Promise<void>[] = []; // one per launched query — NEVER removed
  const scoped: PgExecutor = {
    query(sql, params) {
      if (closing || !TX_STATE.has(tx as unknown as object)) {
        throw new ContractValidationError('DurableTx query issued outside its active transaction scope');
      }
      pending++;
      const p = exec.query(sql, params);
      // Observe settlement WITHOUT consuming the caller's promise, and retain the
      // outcome (a fast rejection cannot disappear before the scope closes).
      settlements.push(p.then(
        () => { pending--; },
        (err) => { pending--; if (!rejectionSeen) { rejectionSeen = true; firstRejection = err; } },
      ));
      return p;
    },
  };
  TX_STATE.set(tx as unknown as object, { db, schema, scoped });
  try {
    const result = await body(tx, scoped);
    closing = true; // deny any NEW query from here
    // SNAPSHOT before draining: any query still running when body returned was
    // launched-but-not-awaited by body — unsafe, must roll back (R11). A query the
    // body properly awaited has already settled, so it is not counted here.
    const hadUnawaitedInFlight = pending > 0;
    // Drain launched queries. If one never settles, the OUTER runScoped deadline
    // fires, aborts the signal, the transactor destroys the connection, the hung
    // query rejects, and this settles — the mechanism never awaits unboundedly.
    await Promise.allSettled(settlements);
    if (rejectionSeen) throw new ContractValidationError(`a query launched in this DurableTx scope rejected — rolling back: ${String((firstRejection as { message?: string })?.message ?? firstRejection)}`);
    if (hadUnawaitedInFlight) throw new ContractValidationError('DurableTx scope ended with unawaited in-flight queries — rolling back');
    return result;
  } finally {
    closing = true;
    TX_STATE.delete(tx as unknown as object); // revoke — no use after this scope
  }
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

/** A validated PostgreSQL schema identifier (lowercase-anchored, no injection). */
function assertSchemaIdentifier(schema: string): void {
  if (!/^[a-z_][a-z0-9_]{0,62}$/.test(schema)) throw new ContractValidationError(`invalid schema identifier: ${schema}`);
}

/**
 * (R7/HIGH1) PIN the schema identity for THIS tx. A pooled connection may carry
 * any default search_path, so every critical tx sets search_path to the
 * configured schema (LOCAL, parameterized — no injection) and asserts
 * current_schema() is exactly that schema. All later unqualified operational SQL
 * — and the manifest attestation — therefore resolve in the SAME pinned schema;
 * readiness for schema A can never bind operations that land in schema B.
 */
async function pinSchema(exec: PgExecutor, schema: string): Promise<void> {
  assertSchemaIdentifier(schema);
  await exec.query('SELECT set_config($1, $2, true)', ['search_path', `${schema},pg_catalog,pg_temp`]);
  const row = (await exec.query(`SELECT current_schema() AS s,
    (current_schemas(true))[1] AS p1,(current_schemas(true))[2] AS p2,
    (current_schemas(true))[3] AS p3,cardinality(current_schemas(true))::int AS n`)).rows[0];
  const cur=row?.s,n=Number(row?.n);
  if (cur !== schema) throw new ContractValidationError(`schema context mismatch: current_schema=${String(cur)} pinned=${schema}`);
  if(row?.p1!==schema||row?.p2!=='pg_catalog'||(n!==2&&!(n===3&&typeof row?.p3==='string'&&row.p3.startsWith('pg_temp_'))))throw new ContractValidationError('schema search path was not pinned with governed authority before pg_temp');
}

/** Enter a critical tx: SERIALIZABLE + pinned schema identity, together. */
async function enterCriticalTx(exec: PgExecutor, schema: string): Promise<void> {
  await assertSerializable(exec);
  await pinSchema(exec, schema);
}

/** Schema version this build provisions/expects. Bump on any DDL change;
 *  `assertSchemaVersion` fails closed on drift so a stale migration cannot be
 *  used with newer code. */
export const HA_OUTBOX_SCHEMA_VERSION = 3 as const;

// Contract fence bound: a fence token is an integer with at most 39 digits
// (FENCE_TOKEN_PATTERN in the contract), i.e. strictly < 10^39. The DDL enforces
// the SAME bound plus integrality (scale 0) so a fractional or oversized value
// cannot be persisted.
const FENCE_MAX_EXCLUSIVE = '1e39';
const JS_SAFE_INT_SQL = '9007199254740991';
const PUBLIC_JWK_CHECK = `
  jsonb_typeof(pub_jwk)='object'
  AND pub_jwk ?& ARRAY['kty','crv','x','y']
  AND (pub_jwk - ARRAY['kty','crv','x','y','key_ops','ext']::text[])='{}'::jsonb
  AND jsonb_typeof(pub_jwk->'kty')='string' AND pub_jwk->>'kty'='EC'
  AND jsonb_typeof(pub_jwk->'crv')='string' AND pub_jwk->>'crv'='P-256'
  AND jsonb_typeof(pub_jwk->'x')='string' AND pub_jwk->>'x' ~ '^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$'
  AND jsonb_typeof(pub_jwk->'y')='string' AND pub_jwk->>'y' ~ '^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$'
  AND NOT (pub_jwk ? 'd')
  AND (NOT (pub_jwk ? 'key_ops') OR pub_jwk->'key_ops'='["verify"]'::jsonb)
  AND (NOT (pub_jwk ? 'ext') OR pub_jwk->'ext'='true'::jsonb)
`;
const PENDING_REGISTRATION_CHECK = `
  jsonb_typeof(registration)='object'
  AND registration ?& ARRAY['name','scope','mode','secretHash','pubJwk']
  AND (registration - ARRAY['name','scope','mode','secretHash','pubJwk','expiresAt','maxRequests','kind','canaryClass']::text[])='{}'::jsonb
  AND jsonb_typeof(registration->'name')='string' AND length(registration->>'name') BETWEEN 1 AND 128
  AND jsonb_typeof(registration->'scope')='string' AND registration->>'scope' IN ('read','read-write','admin')
  AND jsonb_typeof(registration->'mode')='string' AND registration->>'mode' IN ('development','production')
  AND jsonb_typeof(registration->'secretHash')='string' AND registration->>'secretHash' ~ '^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$'
  AND jsonb_typeof(registration->'pubJwk')='object'
  AND registration->'pubJwk' ?& ARRAY['kty','crv','x','y']
  AND ((registration->'pubJwk') - ARRAY['kty','crv','x','y','key_ops','ext']::text[])='{}'::jsonb
  AND jsonb_typeof(registration->'pubJwk'->'kty')='string' AND registration->'pubJwk'->>'kty'='EC'
  AND jsonb_typeof(registration->'pubJwk'->'crv')='string' AND registration->'pubJwk'->>'crv'='P-256'
  AND jsonb_typeof(registration->'pubJwk'->'x')='string' AND registration->'pubJwk'->>'x' ~ '^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$'
  AND jsonb_typeof(registration->'pubJwk'->'y')='string' AND registration->'pubJwk'->>'y' ~ '^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$'
  AND NOT (registration->'pubJwk' ? 'd')
  AND (NOT (registration->'pubJwk' ? 'key_ops') OR registration->'pubJwk'->'key_ops'='["verify"]'::jsonb)
  AND (NOT (registration->'pubJwk' ? 'ext') OR registration->'pubJwk'->'ext'='true'::jsonb)
  AND (NOT (registration ? 'kind') OR (jsonb_typeof(registration->'kind')='string' AND registration->>'kind' IN ('legitimate','ghost')))
  AND (NOT (registration ? 'canaryClass') OR (jsonb_typeof(registration->'canaryClass')='string' AND registration->>'canaryClass' IN ('env_file','docs','registry_exfil')))
  AND ((coalesce(registration->>'kind','legitimate')='ghost' AND registration ? 'canaryClass') OR (coalesce(registration->>'kind','legitimate')='legitimate' AND NOT (registration ? 'canaryClass')))
  AND (NOT (registration ? 'expiresAt') OR (jsonb_typeof(registration->'expiresAt')='number' AND registration->>'expiresAt' ~ '^(0|[1-9][0-9]{0,15})$' AND (registration->>'expiresAt')::numeric <= ${JS_SAFE_INT_SQL}))
  AND (NOT (registration ? 'maxRequests') OR (jsonb_typeof(registration->'maxRequests')='number' AND registration->>'maxRequests' ~ '^(0|[1-9][0-9]{0,15})$' AND (registration->>'maxRequests')::numeric <= ${JS_SAFE_INT_SQL}))
`;

/** Exact pair-authority schema governed by the combined v3 manifest. */
export const BPC_PAIR_PG_SCHEMA = `
CREATE TABLE IF NOT EXISTS bpc_pairs (
  id                  text PRIMARY KEY CHECK (id ~ '^[A-Za-z0-9_-]{1,64}$'),
  name                text NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
  scope               text NOT NULL CHECK (scope IN ('read','read-write','admin')),
  mode                text NOT NULL CHECK (mode IN ('development','production')),
  secret_hash         text NOT NULL CHECK (secret_hash ~ '^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$'),
  pub_jwk             jsonb NOT NULL CHECK ((${PUBLIC_JWK_CHECK}) IS TRUE),
  status              text NOT NULL DEFAULT 'active' CHECK (status IN ('active','locked','expired','rotated','revoked')),
  created             bigint NOT NULL CHECK (created BETWEEN 0 AND ${JS_SAFE_INT_SQL}),
  last_active         bigint CHECK (last_active IS NULL OR last_active BETWEEN 0 AND ${JS_SAFE_INT_SQL}),
  requests            bigint NOT NULL DEFAULT 0 CHECK (requests BETWEEN 0 AND ${JS_SAFE_INT_SQL}),
  failed_sigs         bigint NOT NULL DEFAULT 0 CHECK (failed_sigs BETWEEN 0 AND ${JS_SAFE_INT_SQL}),
  cumulative_failures double precision CHECK (cumulative_failures IS NULL OR (cumulative_failures >= 0 AND cumulative_failures <= '1.7976931348623157e308'::double precision)),
  first_failure_at    bigint CHECK (first_failure_at IS NULL OR first_failure_at BETWEEN 0 AND ${JS_SAFE_INT_SQL}),
  max_requests        bigint CHECK (max_requests IS NULL OR max_requests BETWEEN 0 AND ${JS_SAFE_INT_SQL}),
  kind                text NOT NULL DEFAULT 'legitimate' CHECK (kind IN ('legitimate','ghost')),
  canary_class        text CHECK (canary_class IS NULL OR canary_class IN ('env_file','docs','registry_exfil')),
  expires_at          bigint CHECK (expires_at IS NULL OR expires_at BETWEEN 0 AND ${JS_SAFE_INT_SQL}),
  CHECK ((kind = 'ghost' AND canary_class IS NOT NULL) OR (kind = 'legitimate' AND canary_class IS NULL))
);
CREATE TABLE IF NOT EXISTS bpc_pending (
  token        text PRIMARY KEY CHECK (length(token) BETWEEN 1 AND 256),
  registration jsonb NOT NULL CHECK ((${PENDING_REGISTRATION_CHECK}) IS TRUE),
  requested_at bigint NOT NULL CHECK (requested_at BETWEEN 0 AND ${JS_SAFE_INT_SQL})
);
CREATE INDEX IF NOT EXISTS bpc_pending_requested_at ON bpc_pending (requested_at, token);
`;

/**
 * DDL for the outbox tables. Source-side and receiver-side checkpoints are
 * SEPARATE tables (independent authorities); rows carry a claim marker and a
 * quarantine marker; a per-stream publisher lease enforces single-active,
 * in-order delivery. Every numeric/text column carries a CHECK so a malformed
 * row cannot be persisted:
 *  - sequence non-negative and within JS safe-integer range,
 *  - fence_token a non-negative INTEGER strictly below the contract's 10^39 bound,
 *  - op_digest exactly 64 lowercase hex,
 *  - stream_id / source_epoch non-empty and bounded.
 */
const HA_OUTBOX_INFRA_PG_SCHEMA = `
CREATE TABLE IF NOT EXISTS ha_outbox_meta (
  id             integer PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  schema_version integer NOT NULL CHECK (schema_version >= 1)
);
CREATE TABLE IF NOT EXISTS ha_outbox_fence (
  stream_id     text PRIMARY KEY CHECK (length(stream_id) BETWEEN 1 AND 512),
  fence_token   numeric NOT NULL DEFAULT 0 CHECK (fence_token >= 0 AND scale(fence_token) = 0 AND fence_token < ${FENCE_MAX_EXCLUSIVE})
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
  fence_token   numeric NOT NULL CHECK (fence_token >= 0 AND scale(fence_token) = 0 AND fence_token < ${FENCE_MAX_EXCLUSIVE}),
  op_digest     text NOT NULL CHECK (op_digest ~ '^[0-9a-f]{64}$'),
  mutation      jsonb NOT NULL,                   -- secret-stripped
  published_at  timestamptz,
  acked_at      timestamptz,
  quarantined_at timestamptz,                     -- terminal-reject divergence park
  PRIMARY KEY (stream_id, source_epoch, sequence)
);
CREATE INDEX IF NOT EXISTS ha_outbox_rows_deliverable
  ON ha_outbox_rows (stream_id, sequence) WHERE acked_at IS NULL AND quarantined_at IS NULL;
-- Per-stream publisher lease: only the current lease holder may deliver a
-- stream, and it delivers strictly ascending/contiguous — this is what makes
-- an ordered stream single-active. Parallelism is ACROSS streams only.
CREATE TABLE IF NOT EXISTS ha_outbox_publisher_lease (
  stream_id     text PRIMARY KEY CHECK (length(stream_id) BETWEEN 1 AND 512),
  lease_token   text,
  lease_until   timestamptz
);
-- Terminally-rejected records (fork/stale/unsanitized/epoch): parked for
-- investigation, NEVER acked as delivered and NEVER silently dropped.
CREATE TABLE IF NOT EXISTS ha_outbox_quarantine (
  stream_id     text NOT NULL CHECK (length(stream_id) BETWEEN 1 AND 512),
  source_epoch  text NOT NULL CHECK (length(source_epoch) BETWEEN 1 AND 512),
  sequence      bigint NOT NULL CHECK (sequence >= 1 AND sequence <= 9007199254740991),
  op_digest     text NOT NULL CHECK (op_digest ~ '^[0-9a-f]{64}$'),
  decision      text NOT NULL,
  quarantined_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (stream_id, source_epoch, sequence)
);
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

export const HA_OUTBOX_PG_SCHEMA = `
${HA_OUTBOX_INFRA_PG_SCHEMA}
-- Authorization authority is attested with the outbox so one readiness token
-- covers both sides of every transactionally-coupled pair mutation.
${BPC_PAIR_PG_SCHEMA}
-- NOTE: the DDL NEVER stamps the version. Stamping happens only through
-- provisionSchemaVersion() / adoptCurrentSchemaVersion(), each of which runs a full
-- catalog attestation (attestSchema) in the SAME serializable tx first, so a
-- malformed/partial/foreign-schema layout can never be labelled a valid version.
`;

/** Tables that make up the HA-outbox schema (attestation scope). */
const HA_OUTBOX_TABLES = [
  'ha_outbox_meta', 'ha_outbox_fence', 'ha_outbox_source_checkpoint',
  'ha_outbox_receiver_checkpoint', 'ha_outbox_rows', 'ha_outbox_publisher_lease',
  'ha_outbox_quarantine', 'ha_outbox_applied', 'bpc_pairs', 'bpc_pending',
] as const;

/**
 * (R5/R6/R8/HIGH) Pinned manifest of the EXACT expected schema in the CURRENT
 * schema: every table's columns (ordinal, name, type, nullability, default),
 * every PK/CHECK/unique/FK constraint, every index definition, each table's
 * relkind/persistence and RLS posture (relrowsecurity/relforcerowsecurity), every
 * NON-internal trigger (def + enabled state), and every RLS policy (cmd, roles,
 * USING/WITH CHECK). Constant-time compared at attestation; ANY deviation — a
 * missing/altered/reordered column, a weakened/removed CHECK, a wrong PK, a
 * missing/wrong index, a table turned into a view/unlogged, an added trigger or
 * RLS policy, or same-named objects in a different schema — changes the digest
 * and fails closed. PostgreSQL-major-version specific (catalog rendering): a
 * supported-PG bump requires recomputing this via schemaManifest().
 */
export const HA_OUTBOX_SCHEMA_MANIFEST = '7af22efd9ed7828bdf2901fc9b05230cff9c3bd18d62f406305a307d40030792';

/** Canonical fingerprint of the live schema in `current_schema()`. Deterministic
 *  (no oids/timestamps); identical normalization to the pinned manifest. */
export async function schemaManifest(exec: PgExecutor): Promise<string> {
  const tables = HA_OUTBOX_TABLES as unknown as string[];
  const cols = (await exec.query(
    `SELECT table_name, ordinal_position, column_name, udt_name, is_nullable, coalesce(column_default, '') AS cd
     FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = ANY($1)`,
    [tables],
  )).rows;
  const cons = (await exec.query(
    `SELECT rel.relname AS t, c.contype, pg_get_constraintdef(c.oid) AS def
     FROM pg_constraint c JOIN pg_class rel ON rel.oid = c.conrelid JOIN pg_namespace n ON n.oid = rel.relnamespace
     WHERE n.nspname = current_schema() AND rel.relname = ANY($1) AND c.contype IN ('p','c','u','f')`,
    [tables],
  )).rows;
  const idx = (await exec.query(
    `SELECT tablename AS t, indexname, indexdef FROM pg_indexes WHERE schemaname = current_schema() AND tablename = ANY($1)`,
    [tables],
  )).rows;
  // (R8) relation kind/persistence + row-level-security posture per table.
  const rel = (await exec.query(
    `SELECT rel.relname AS t, rel.relkind, rel.relpersistence, rel.relrowsecurity, rel.relforcerowsecurity
     FROM pg_class rel JOIN pg_namespace n ON n.oid = rel.relnamespace
     WHERE n.nspname = current_schema() AND rel.relname = ANY($1)`,
    [tables],
  )).rows;
  // (R8) all NON-internal triggers (definition + enabled state).
  const trig = (await exec.query(
    `SELECT rel.relname AS t, tg.tgname, tg.tgenabled, pg_get_triggerdef(tg.oid) AS def
     FROM pg_trigger tg JOIN pg_class rel ON rel.oid = tg.tgrelid JOIN pg_namespace n ON n.oid = rel.relnamespace
     WHERE n.nspname = current_schema() AND rel.relname = ANY($1) AND NOT tg.tgisinternal`,
    [tables],
  )).rows;
  // (R8) RLS policies: cmd, roles, USING/WITH CHECK expressions.
  const pol = (await exec.query(
    `SELECT rel.relname AS t, p.polname, p.polcmd,
            coalesce((SELECT string_agg(rolname, ',' ORDER BY rolname) FROM pg_roles WHERE oid = ANY(p.polroles)), '') AS roles,
            coalesce(pg_get_expr(p.polqual, p.polrelid), '') AS qual,
            coalesce(pg_get_expr(p.polwithcheck, p.polrelid), '') AS withcheck
     FROM pg_policy p JOIN pg_class rel ON rel.oid = p.polrelid JOIN pg_namespace n ON n.oid = rel.relnamespace
     WHERE n.nspname = current_schema() AND rel.relname = ANY($1)`,
    [tables],
  )).rows;
  const stripSchema = (s: string) => s.replace(/ ON \w+\./, ' ON ');
  const parts: string[] = [];
  for (const r of cols) parts.push(`COL|${r.table_name}|${r.ordinal_position}|${r.column_name}|${r.udt_name}|${r.is_nullable}|${r.cd}`);
  for (const r of cons) parts.push(`CON|${r.t}|${r.contype}|${r.def}`);
  for (const r of idx) parts.push(`IDX|${r.t}|${r.indexname}|${stripSchema(String(r.indexdef))}`);
  for (const r of rel) parts.push(`REL|${r.t}|${r.relkind}|${r.relpersistence}|${r.relrowsecurity}|${r.relforcerowsecurity}`);
  for (const r of trig) parts.push(`TRG|${r.t}|${r.tgname}|${r.tgenabled}|${stripSchema(String(r.def))}`);
  for (const r of pol) parts.push(`POL|${r.t}|${r.polname}|${r.polcmd}|${r.roles}|${r.qual}|${r.withcheck}`);
  parts.sort();
  return createHash('sha256').update(parts.join('\n'), 'utf8').digest('hex');
}

/** (R5/HIGH) Attest the live schema exactly matches the pinned manifest, or fail
 *  closed. Scoped to current_schema() (no cross-schema same-name spoof). */
export async function attestSchema(exec: PgExecutor): Promise<void> {
  const found = await schemaManifest(exec);
  if (!digestEquals(found, HA_OUTBOX_SCHEMA_MANIFEST)) {
    throw new ContractValidationError('ha_outbox schema attestation failed: live catalog does not match the expected manifest');
  }
}

/**
 * (R8/HIGH) UNFORGEABLE schema-readiness capability. It is only minted by
 * `assertSchemaReady`/`provisionSchemaVersion`/`adoptCurrentSchemaVersion` after a
 * full in-tx attestation, and is bound to the exact `PgTransactor` identity, the
 * pinned `schema`, and the attested manifest+version digest. Constructors REQUIRE
 * one and reject a token minted for a different transactor or schema — so a
 * mechanism object cannot be built (and therefore cannot operate) without a
 * verified, identity-bound readiness proof. The type is opaque; its state lives
 * in a module-private WeakMap and cannot be reached or forged by callers.
 *
 * PRIVILEGE-SEPARATION NOTE: the token establishes readiness at STARTUP. It does
 * NOT (and cannot) prevent a role holding DDL privilege from mutating the schema
 * afterwards. Preserving readiness at runtime is a database privilege-separation
 * responsibility: the runtime identity MUST NOT hold DDL/migration rights, so the
 * attested structure cannot be altered under it. #16 stays OPEN.
 */
const READY_BRAND = Symbol('ha_outbox_schema_ready');
export interface SchemaReadyToken { readonly [READY_BRAND]: true }
interface ReadyState { db: PgTransactor; schema: string; manifest: string; version: number }
const READY_STATE = new WeakMap<object, ReadyState>();

function mintReadyToken(state: ReadyState): SchemaReadyToken {
  const token = Object.freeze({ [READY_BRAND]: true as const });
  READY_STATE.set(token, state);
  return token as SchemaReadyToken;
}

/** Validate a readiness token (brand + optional transactor identity) and return
 *  its bound schema. Throws on a forged/foreign token or a db/schema mismatch. */
function requireReady(token: SchemaReadyToken, db?: PgTransactor, expectSchema?: string): string {
  const st = READY_STATE.get(token as unknown as object);
  if (!st) throw new ContractValidationError('invalid schema-readiness capability (forged or foreign token)');
  if (db !== undefined && st.db !== db) throw new ContractValidationError('schema-readiness token is bound to a different PgTransactor');
  if (expectSchema !== undefined && st.schema !== expectSchema) throw new ContractValidationError('schema-readiness token schema mismatch');
  if (st.manifest !== HA_OUTBOX_SCHEMA_MANIFEST || st.version !== HA_OUTBOX_SCHEMA_VERSION) throw new ContractValidationError('schema-readiness token attests a different manifest/version');
  return st.schema;
}

/**
 * @internal @deprecated — version-only check. Callers MUST NOT use this as a
 * readiness gate: it does NOT detect structural drift (an ALTER/DROP that left
 * meta untouched). Use `assertSchemaReady`. Retained (unexported from the package
 * index) only to demonstrate the weaker-gate bypass in tests. Requires the pinned
 * schema so it reads the intended authority.
 */
export async function assertSchemaVersionOnly(db: PgTransactor, schema: string): Promise<void> {
  await db.transaction(async (exec) => {
    await enterCriticalTx(exec, schema);
    const rows = (await exec.query('SELECT schema_version FROM ha_outbox_meta WHERE id = 1')).rows;
    if (!rows.length) throw new ContractValidationError('ha_outbox schema is not provisioned (no meta row)');
    const found = safeSeq(rows[0].schema_version, 'schema_version');
    if (found !== HA_OUTBOX_SCHEMA_VERSION) throw new ContractValidationError(`ha_outbox schema version mismatch: db=${found} expected=${HA_OUTBOX_SCHEMA_VERSION}`);
  });
}

/** Inline version-check helper (assumes the tx already entered/pinned). */
async function assertVersionInTx(exec: PgExecutor): Promise<void> {
  const rows = (await exec.query('SELECT schema_version FROM ha_outbox_meta WHERE id = 1')).rows;
  if (!rows.length) throw new ContractValidationError('ha_outbox schema is not provisioned (no meta row)');
  const found = safeSeq(rows[0].schema_version, 'schema_version');
  if (found !== HA_OUTBOX_SCHEMA_VERSION) throw new ContractValidationError(`ha_outbox schema version mismatch: db=${found} expected=${HA_OUTBOX_SCHEMA_VERSION}`);
}

/**
 * (R6/R8/HIGH) The RUNTIME READINESS GATE. In ONE serializable tx, in the pinned
 * schema, it runs the FULL manifest attestation (catches post-provision drift)
 * AND the version check, then MINTS an unforgeable `SchemaReadyToken` bound to
 * this transactor + schema + attested manifest/version. Constructors require the
 * token, so a mechanism object cannot be built without this proof.
 */
export async function assertSchemaReady(db: PgTransactor, schema: string): Promise<SchemaReadyToken> {
  await db.transaction(async (exec) => {
    await enterCriticalTx(exec, schema);
    await attestSchema(exec);
    await assertVersionInTx(exec);
  });
  return mintReadyToken({ db, schema, manifest: HA_OUTBOX_SCHEMA_MANIFEST, version: HA_OUTBOX_SCHEMA_VERSION });
}

/**
 * (R5/R7/HIGH2) FRESH provisioning in the PINNED schema: attest the fully-fresh
 * catalog, then stamp the current version with a PLAIN insert whose effect is
 * asserted. An existing meta row at exactly the current version is an explicit
 * idempotent no-op; ANY other existing row (future/lower/multiple) is REJECTED.
 * Returns a readiness token on success.
 */
export async function provisionSchemaVersion(db: PgTransactor, schema: string): Promise<SchemaReadyToken> {
  await db.transaction(async (exec) => {
    await enterCriticalTx(exec, schema);
    await attestSchema(exec);
    const rows = (await exec.query('SELECT schema_version FROM ha_outbox_meta FOR UPDATE')).rows;
    if (rows.length > 1) throw new ContractValidationError('multiple schema-version authority rows');
    if (rows.length === 1) {
      const cur = safeSeq(rows[0].schema_version, 'schema_version');
      if (cur === HA_OUTBOX_SCHEMA_VERSION) return; // idempotent
      throw new ContractValidationError(`fresh provisioning refused: meta already at version ${cur}`);
    }
    const res = await exec.query(`INSERT INTO ha_outbox_meta (id, schema_version) VALUES (1, ${HA_OUTBOX_SCHEMA_VERSION})`);
    affectedOne(res, 'fresh schema provision');
  });
  return mintReadyToken({ db, schema, manifest: HA_OUTBOX_SCHEMA_MANIFEST, version: HA_OUTBOX_SCHEMA_VERSION });
}

/**
 * (R4/R5/R6/R7/R8) ADOPT the current schema version for an install whose catalog
 * ALREADY EXACTLY matches this build's manifest (renamed from migrateSchemaToCurrent:
 * it does NOT migrate an old DDL layout — it attests the exact current structure
 * and adopts the version). The ONLY path that may bump an existing meta row, and
 * FORWARD-ONLY: already-current is a no-op; a FUTURE version is REFUSED (never
 * downgraded); a malformed/partial/foreign layout fails attestation. (Real
 * structural migrations between versions are a separate, future concern.)
 * Returns a readiness token on success.
 */
export async function adoptCurrentSchemaVersion(db: PgTransactor, schema: string): Promise<SchemaReadyToken> {
  await db.transaction(async (exec) => {
    await enterCriticalTx(exec, schema);
    await attestSchema(exec);
    const rows = (await exec.query('SELECT schema_version FROM ha_outbox_meta FOR UPDATE')).rows;
    if (rows.length > 1) throw new ContractValidationError('multiple schema-version authority rows');
    if (rows.length === 1) {
      const cur = safeSeq(rows[0].schema_version, 'schema_version');
      if (cur === HA_OUTBOX_SCHEMA_VERSION) return; // no-op
      if (cur > HA_OUTBOX_SCHEMA_VERSION) throw new ContractValidationError(`refusing to downgrade schema version ${cur} -> ${HA_OUTBOX_SCHEMA_VERSION}`);
    }
    const res = await exec.query(
      `INSERT INTO ha_outbox_meta (id, schema_version) VALUES (1, ${HA_OUTBOX_SCHEMA_VERSION})
       ON CONFLICT (id) DO UPDATE SET schema_version = EXCLUDED.schema_version`,
    );
    affectedOne(res, 'schema version adopt');
  });
  return mintReadyToken({ db, schema, manifest: HA_OUTBOX_SCHEMA_MANIFEST, version: HA_OUTBOX_SCHEMA_VERSION });
}

async function executeDdlBatch(exec:PgExecutor,sql:string):Promise<void>{
  for(const statement of sql.split(';').map(part=>part.trim()).filter(Boolean))await exec.query(statement);
}

/**
 * One-time preparation for a standalone legacy PairStore installation that has
 * only `bpc_pairs` and `bpc_pending`. Under authority locks it rejects unsafe
 * relation posture or any pre-existing HA object, creates the outbox
 * infrastructure without touching pair rows, and stamps the legacy version-2
 * authority. `migrateLegacyPairAuthorityToV3` must run next and revalidates all
 * legacy columns/data before advancing to v3.
 */
export async function prepareLegacyPairAuthorityV2ForMigration(db: PgTransactor, schema: string): Promise<void> {
  assertSchemaIdentifier(schema);
  const lockedTransaction=db.transactionWithInitialExclusiveLocks;
  if(typeof lockedTransaction!=='function')throw new ContractValidationError('legacy preparation requires a transactor that locks authority before establishing its SERIALIZABLE snapshot');
  await lockedTransaction.call(db,[{schema,table:'bpc_pairs'},{schema,table:'bpc_pending'}],async(exec)=>{
    await enterCriticalTx(exec,schema);
    const posture=(await exec.query(`SELECT rel.relname,rel.relkind,rel.relpersistence,rel.relrowsecurity,rel.relforcerowsecurity,
      (SELECT count(*)::int FROM pg_trigger tg WHERE tg.tgrelid=rel.oid AND NOT tg.tgisinternal) AS triggers,
      (SELECT count(*)::int FROM pg_policy p WHERE p.polrelid=rel.oid) AS policies,
      (SELECT count(*)::int FROM pg_rewrite rw WHERE rw.ev_class=rel.oid) AS rules,
      (SELECT count(*)::int FROM pg_inherits i WHERE i.inhrelid=rel.oid OR i.inhparent=rel.oid) AS inheritance
      FROM pg_class rel JOIN pg_namespace n ON n.oid=rel.relnamespace
      WHERE n.nspname=current_schema() AND rel.relname IN ('bpc_pairs','bpc_pending')`)).rows;
    if(posture.length!==2||posture.some(row=>row.relkind!=='r'||row.relpersistence!=='p'||row.relrowsecurity!==false||row.relforcerowsecurity!==false||Number(row.triggers)!==0||Number(row.policies)!==0||Number(row.rules)!==0||Number(row.inheritance)!==0))throw new ContractValidationError('legacy pair preparation found unsafe relation/RLS/policy/trigger/rule/inheritance posture');
    const infraNames=['ha_outbox_meta','ha_outbox_fence','ha_outbox_source_checkpoint','ha_outbox_receiver_checkpoint','ha_outbox_rows','ha_outbox_publisher_lease','ha_outbox_quarantine','ha_outbox_applied'];
    const collisions=(await exec.query(`SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=current_schema() AND c.relname=ANY($1::text[])`,[infraNames])).rows;
    if(collisions.length)throw new ContractValidationError('legacy pair preparation requires no pre-existing HA/outbox objects');
    await executeDdlBatch(exec,HA_OUTBOX_INFRA_PG_SCHEMA);
    affectedOne(await exec.query('INSERT INTO ha_outbox_meta(id,schema_version) VALUES(1,2)'),'legacy schema version preparation');
  });
}

/**
 * One-time, forward-only migration from the legacy v2 standalone PairStore
 * tables to the v3 attested pair-authority layout. It rebuilds both authority
 * tables inside the same SERIALIZABLE transaction, so constraint validation,
 * data copy, table swap, full combined-schema attestation, and version advance
 * either all commit or all roll back. It never repairs/adopts an arbitrary
 * layout and never downgrades a future marker.
 */
export async function migrateLegacyPairAuthorityToV3(db: PgTransactor, schema: string): Promise<SchemaReadyToken> {
  assertSchemaIdentifier(schema);
  const lockedTransaction = db.transactionWithInitialExclusiveLocks;
  if (typeof lockedTransaction !== 'function') {
    throw new ContractValidationError('legacy migration requires a transactor that locks authority before establishing its SERIALIZABLE snapshot');
  }
  await lockedTransaction.call(db, [
    { schema, table: 'bpc_pairs' },
    { schema, table: 'bpc_pending' },
  ], async (exec) => {
    await enterCriticalTx(exec, schema);
    const versions = (await exec.query('SELECT schema_version FROM ha_outbox_meta WHERE id = 1 FOR UPDATE')).rows;
    if (versions.length !== 1) throw new ContractValidationError('legacy migration requires exactly one schema-version authority row');
    const current = safeSeq(versions[0].schema_version, 'schema_version');
    if (current !== 2) throw new ContractValidationError(`legacy migration requires schema version 2; found ${current}`);
    const columns = (await exec.query(
      `SELECT table_name, column_name, udt_name FROM information_schema.columns
       WHERE table_schema = current_schema() AND table_name IN ('bpc_pairs','bpc_pending')
       ORDER BY table_name, ordinal_position`,
    )).rows;
    const expected = new Map<string, Set<string>>([
      ['bpc_pairs', new Set(['id:text','name:text','scope:text','mode:text','secret_hash:text','pub_jwk:jsonb','status:text','created:int8','last_active:int8','requests:int4|int8','failed_sigs:int4|int8','cumulative_failures:float8','first_failure_at:int8','max_requests:int8','kind:text','canary_class:text','expires_at:int8'])],
      ['bpc_pending', new Set(['token:text','registration:jsonb','requested_at:int8'])],
    ]);
    const seen = new Map<string, Set<string>>([['bpc_pairs', new Set()], ['bpc_pending', new Set()]]);
    for (const row of columns) {
      const table = String(row.table_name), column = String(row.column_name), type = String(row.udt_name);
      const allowed = expected.get(table); if (!allowed) throw new ContractValidationError('legacy pair schema contains an unexpected table');
      const match = [...allowed].find((entry) => { const [name, types] = entry.split(':'); return name === column && types.split('|').includes(type); });
      if (!match) throw new ContractValidationError(`legacy pair schema has an unexpected column/type: ${table}.${column}:${type}`);
      seen.get(table)!.add(match);
    }
    for (const [table, required] of expected) if (seen.get(table)!.size !== required.size) throw new ContractValidationError(`legacy pair schema is incomplete: ${table}`);
    const posture = (await exec.query(
      `SELECT rel.relname AS table_name, rel.relkind, rel.relpersistence, rel.relrowsecurity, rel.relforcerowsecurity,
              (SELECT count(*)::int FROM pg_trigger tg WHERE tg.tgrelid=rel.oid AND NOT tg.tgisinternal) AS triggers,
              (SELECT count(*)::int FROM pg_policy p WHERE p.polrelid=rel.oid) AS policies,
              (SELECT count(*)::int FROM pg_rewrite rw WHERE rw.ev_class=rel.oid) AS rules,
              (SELECT count(*)::int FROM pg_inherits i WHERE i.inhrelid=rel.oid OR i.inhparent=rel.oid) AS inheritance
       FROM pg_class rel JOIN pg_namespace n ON n.oid=rel.relnamespace
       WHERE n.nspname=current_schema() AND rel.relname IN ('bpc_pairs','bpc_pending')`,
    )).rows;
    if (posture.length !== 2 || posture.some((row) => row.relkind !== 'r' || row.relpersistence !== 'p' || row.relrowsecurity !== false || row.relforcerowsecurity !== false || Number(row.triggers)!==0 || Number(row.policies)!==0 || Number(row.rules)!==0 || Number(row.inheritance)!==0)) {
      throw new ContractValidationError('legacy pair schema has unsafe relation/RLS/policy/trigger/rule/inheritance posture');
    }
    const collisions = (await exec.query(
      `SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
       WHERE n.nspname=current_schema() AND c.relname IN ('bpc_pairs_v3_stage','bpc_pending_v3_stage','bpc_pairs_v2_backup','bpc_pending_v2_backup')`,
    )).rows;
    if (collisions.length) throw new ContractValidationError('legacy migration staging object already exists');
    await executeDdlBatch(exec,`
      CREATE TABLE bpc_pairs_v3_stage (
        id text PRIMARY KEY CHECK (id ~ '^[A-Za-z0-9_-]{1,64}$'), name text NOT NULL CHECK (length(name) BETWEEN 1 AND 128),
        scope text NOT NULL CHECK (scope IN ('read','read-write','admin')), mode text NOT NULL CHECK (mode IN ('development','production')),
        secret_hash text NOT NULL CHECK (secret_hash ~ '^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$'), pub_jwk jsonb NOT NULL CHECK ((${PUBLIC_JWK_CHECK}) IS TRUE),
        status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','locked','expired','rotated','revoked')), created bigint NOT NULL CHECK (created BETWEEN 0 AND ${JS_SAFE_INT_SQL}),
        last_active bigint CHECK (last_active IS NULL OR last_active BETWEEN 0 AND ${JS_SAFE_INT_SQL}), requests bigint NOT NULL DEFAULT 0 CHECK (requests BETWEEN 0 AND ${JS_SAFE_INT_SQL}),
        failed_sigs bigint NOT NULL DEFAULT 0 CHECK (failed_sigs BETWEEN 0 AND ${JS_SAFE_INT_SQL}), cumulative_failures double precision CHECK (cumulative_failures IS NULL OR (cumulative_failures>=0 AND cumulative_failures <= '1.7976931348623157e308'::double precision)),
        first_failure_at bigint CHECK (first_failure_at IS NULL OR first_failure_at BETWEEN 0 AND ${JS_SAFE_INT_SQL}), max_requests bigint CHECK (max_requests IS NULL OR max_requests BETWEEN 0 AND ${JS_SAFE_INT_SQL}),
        kind text NOT NULL DEFAULT 'legitimate' CHECK (kind IN ('legitimate','ghost')), canary_class text CHECK (canary_class IS NULL OR canary_class IN ('env_file','docs','registry_exfil')),
        expires_at bigint CHECK (expires_at IS NULL OR expires_at BETWEEN 0 AND ${JS_SAFE_INT_SQL}), CHECK ((kind='ghost' AND canary_class IS NOT NULL) OR (kind='legitimate' AND canary_class IS NULL))
      );
      CREATE TABLE bpc_pending_v3_stage (
        token text PRIMARY KEY CHECK (length(token) BETWEEN 1 AND 256), registration jsonb NOT NULL CHECK ((${PENDING_REGISTRATION_CHECK}) IS TRUE),
        requested_at bigint NOT NULL CHECK (requested_at BETWEEN 0 AND ${JS_SAFE_INT_SQL})
      );
    `);
    const sourcePairs = Number((await exec.query('SELECT count(*)::int AS n FROM bpc_pairs')).rows[0].n);
    const sourcePending = Number((await exec.query('SELECT count(*)::int AS n FROM bpc_pending')).rows[0].n);
    if (sourcePairs > 0) {
      const copied = await exec.query('INSERT INTO bpc_pairs_v3_stage SELECT id,name,scope,mode,secret_hash,pub_jwk,status,created,last_active,requests,failed_sigs,cumulative_failures,first_failure_at,max_requests,kind,canary_class,expires_at FROM bpc_pairs');
      if (copied.rowCount !== sourcePairs) throw new ContractValidationError(`legacy pair copy affected ${copied.rowCount}; expected ${sourcePairs}`);
    }
    if (sourcePending > 0) {
      const copied = await exec.query('INSERT INTO bpc_pending_v3_stage SELECT token,registration,requested_at FROM bpc_pending');
      if (copied.rowCount !== sourcePending) throw new ContractValidationError(`legacy pending copy affected ${copied.rowCount}; expected ${sourcePending}`);
    }
    const pairMismatch = (await exec.query(`SELECT EXISTS(
      (SELECT id,name,scope,mode,secret_hash,pub_jwk,status,created,last_active,requests::bigint,failed_sigs::bigint,cumulative_failures,first_failure_at,max_requests,kind,canary_class,expires_at FROM bpc_pairs
       EXCEPT SELECT id,name,scope,mode,secret_hash,pub_jwk,status,created,last_active,requests,failed_sigs,cumulative_failures,first_failure_at,max_requests,kind,canary_class,expires_at FROM bpc_pairs_v3_stage)
      UNION ALL
      (SELECT id,name,scope,mode,secret_hash,pub_jwk,status,created,last_active,requests,failed_sigs,cumulative_failures,first_failure_at,max_requests,kind,canary_class,expires_at FROM bpc_pairs_v3_stage
       EXCEPT SELECT id,name,scope,mode,secret_hash,pub_jwk,status,created,last_active,requests::bigint,failed_sigs::bigint,cumulative_failures,first_failure_at,max_requests,kind,canary_class,expires_at FROM bpc_pairs)
    ) AS mismatch`)).rows[0].mismatch;
    const pendingMismatch = (await exec.query(`SELECT EXISTS(
      (SELECT token,registration,requested_at FROM bpc_pending EXCEPT SELECT token,registration,requested_at FROM bpc_pending_v3_stage)
      UNION ALL
      (SELECT token,registration,requested_at FROM bpc_pending_v3_stage EXCEPT SELECT token,registration,requested_at FROM bpc_pending)
    ) AS mismatch`)).rows[0].mismatch;
    if (pairMismatch !== false || pendingMismatch !== false) throw new ContractValidationError('legacy pair migration copy did not preserve exact authority rows');
    await executeDdlBatch(exec,`
      ALTER TABLE bpc_pairs RENAME TO bpc_pairs_v2_backup;
      ALTER TABLE bpc_pending RENAME TO bpc_pending_v2_backup;
      DROP TABLE bpc_pairs_v2_backup, bpc_pending_v2_backup;
      ALTER TABLE bpc_pairs_v3_stage RENAME TO bpc_pairs;
      ALTER TABLE bpc_pending_v3_stage RENAME TO bpc_pending;
      ALTER INDEX bpc_pairs_v3_stage_pkey RENAME TO bpc_pairs_pkey;
      ALTER INDEX bpc_pending_v3_stage_pkey RENAME TO bpc_pending_pkey;
      CREATE INDEX bpc_pending_requested_at ON bpc_pending (requested_at, token);
    `);
    await attestSchema(exec);
    affectedOne(await exec.query(`UPDATE ha_outbox_meta SET schema_version=${HA_OUTBOX_SCHEMA_VERSION} WHERE id=1 AND schema_version=2`), 'legacy schema version advance');
  });
  return mintReadyToken({ db, schema, manifest: HA_OUTBOX_SCHEMA_MANIFEST, version: HA_OUTBOX_SCHEMA_VERSION });
}

export interface PgOutboxOptions<Raw, Clean> {
  streamId: string;
  sanitizer: MutationSanitizer<Raw, Clean>;
  /** Max unpublished/unacked rows before admission fails closed. */
  maxPendingRows: number;
  /** Backpressure policy surfaced to the publisher contract. */
  backpressure: PublisherBackpressure;
  /** (R12) upper bound on one withOutboxTx scope (body + drain); default 30s. */
  scopeDeadlineMs?: number;
  /** Optional external source-authority fence. When a mutation was appended in
   *  this scope, the hook runs after all caller DML and immediately before the
   *  transaction callback returns. A rejection rolls the entire mutation and
   *  outbox row back. */
  preCommitCheck?: (exec: PgExecutor) => Promise<void>;
}

/**
 * The source-side durable outbox. `withOutboxTx` opens ONE serializable DB
 * transaction and yields a bound `DurableTx`; `appendInTx` runs entirely inside
 * it: fence check, admission (bounded), sequence allocation, sanitize, digest,
 * and row insert all commit or roll back together with the caller's mutation.
 */
export class PgDurableOutbox<Raw, Clean> implements DurableOutbox<Raw, Clean, PgBackend> {
  readonly sanitizer: MutationSanitizer<Raw, Clean>;
  private readonly schema: string;
  private readonly scopeDeadlineMs: number;
  private readonly mutatingScopes = new WeakSet<object>();
  constructor(private readonly db: PgTransactor, ready: SchemaReadyToken, private readonly opts: PgOutboxOptions<Raw, Clean>) {
    if (!Number.isSafeInteger(opts.maxPendingRows) || opts.maxPendingRows <= 0) {
      throw new ContractValidationError('maxPendingRows must be a positive safe integer');
    }
    this.scopeDeadlineMs = validateDeadlineMs(opts.scopeDeadlineMs ?? DEFAULT_SCOPE_DEADLINE_MS, 'scopeDeadlineMs');
    this.schema = requireReady(ready, db); // (R8) reject a forged/foreign-db token
    this.sanitizer = opts.sanitizer;
  }

  /** Open a durable tx and run `fn` with the bound handle. The caller performs
   *  its authoritative mutation and `appendInTx` inside `fn`; both commit atomically.
   *  (R13) The deadline wraps the WHOLE transaction — including enterCriticalTx —
   *  and aborts the transactor's signal on timeout. */
  async withOutboxTx<T>(fn: (tx: PgTx, exec: PgExecutor) => Promise<T>): Promise<T> {
    return runScoped(this.scopeDeadlineMs, (signal) => this.db.transaction(async (exec) => {
      await enterCriticalTx(exec, this.schema);
      // hand the caller ONLY the capability-scoped proxy (never the raw exec), so
      // their own mutations are also liveness-checked and drained/rolled back.
      return withBoundTx(exec, this.db, this.schema, async (tx, scoped) => {
        const result = await fn(tx, scoped);
        if (this.mutatingScopes.has(tx as object) && this.opts.preCommitCheck) {
          await this.opts.preCommitCheck(scoped);
        }
        return result;
      });
    }, { signal }));
  }

  async appendInTx(
    tx: PgTx,
    input: { streamId: string; rawMutation: Raw; fenceToken: FenceToken },
  ): Promise<OutboxRecordHeader> {
    // Reject a forged, foreign or expired capability before inspecting caller
    // input or invoking its sanitizer.
    const exec = execOfBound(tx, this.db, this.schema);
    this.mutatingScopes.add(tx as object);
    // Snapshot and sanitize synchronously before the first await. A caller cannot
    // mutate raw input while fence/admission/checkpoint queries are pending.
    const captured = snapshotAppendInput(input);
    const clean = this.sanitizer.sanitize(captured.rawMutation);
    const mutation = snapshotJson(clean, 'sanitized mutation') as SanitizedMutation<Clean>;
    const streamId = captured.streamId;
    if (streamId !== this.opts.streamId) throw new ContractValidationError('streamId mismatch for this outbox');
    const fenceDecimal = fenceTokenToDecimal(captured.fenceToken);

    // (h) validate the presented fence token against the authoritative persisted
    // token under a row lock; stale token fails closed.
    const fenceRows = (await exec.query('SELECT fence_token FROM ha_outbox_fence WHERE stream_id = $1 FOR UPDATE', [streamId])).rows;
    if (!fenceRows.length) throw new ContractValidationError('no authoritative fence row — stream not provisioned (fail closed)');
    const persistedFence = BigInt(String(fenceRows[0].fence_token));
    if (captured.fenceToken !== persistedFence) throw new StaleFenceError(captured.fenceToken, persistedFence);

    // (11) admission INSIDE the tx: over the bound → abort the mutation.
    const pending = safeSeq((await exec.query('SELECT count(*)::bigint AS n FROM ha_outbox_rows WHERE stream_id = $1 AND acked_at IS NULL AND quarantined_at IS NULL', [streamId])).rows[0].n, 'pending-count');
    if (pending >= this.opts.maxPendingRows) throw new OutboxBackpressureError(this.opts.backpressure);

    // (i) allocate the next sequence within the tx (source checkpoint = allocator).
    const cpRows = (await exec.query('SELECT source_epoch, sequence FROM ha_outbox_source_checkpoint WHERE stream_id = $1 FOR UPDATE', [streamId])).rows;
    if (!cpRows.length) throw new ContractValidationError('stream not provisioned (no source checkpoint row)');
    const sourceEpoch = String(cpRows[0].source_epoch);
    // (HIGH6) safe-integer allocation — never Number(bigint)+1 on an unsafe value.
    const cur = safeSeq(cpRows[0].sequence, 'source.checkpoint.sequence');
    if (cur >= Number.MAX_SAFE_INTEGER) throw new ContractValidationError('source sequence exhausted safe-integer range');
    const nextSeq = cur + 1;

    // (10) digest the detached, frozen sanitized snapshot captured at entry.
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

/** (#4/HIGH2/H1) Record-bound acknowledgement the receiver returns. The tuple/
 *  digest prove ECHO only; `receiverId`/`keyId`/`issuedAt`/`signature` let an
 *  `AckReceiptVerifier` prove the ACK came from the authorized receiver over the
 *  record; `decision` is the SIGNED receiver verdict — the source acts on it
 *  (only applied|duplicate-ok removes the row from the outbox). */
export interface AckReceipt {
  streamId: string;
  sourceEpoch: string;
  sequence: number;
  opDigest: string;
  decision: ReceiverDecision;
  receiverId: string;
  keyId: string;
  issuedAt: string;
  signature: string;
}

function snapshotAckReceipt(receipt: AckReceipt): AckReceipt {
  const snapshot = snapshotJson(receipt, 'ACK receipt');
  assertExactOwnKeys(snapshot as object, ['streamId', 'sourceEpoch', 'sequence', 'opDigest', 'decision', 'receiverId', 'keyId', 'issuedAt', 'signature'], 'ACK receipt');
  if (typeof snapshot.streamId !== 'string' || typeof snapshot.sourceEpoch !== 'string' ||
      !Number.isSafeInteger(snapshot.sequence) || snapshot.sequence < 1 ||
      typeof snapshot.opDigest !== 'string' || typeof snapshot.decision !== 'string' ||
      typeof snapshot.receiverId !== 'string' || typeof snapshot.keyId !== 'string' ||
      typeof snapshot.issuedAt !== 'string' || typeof snapshot.signature !== 'string') {
    throw new ContractValidationError('ACK receipt has invalid field types');
  }
  return snapshot;
}
/** (HIGH2/H1) Verifies a receipt is a genuine, authorized acknowledgement of
 *  THIS record AND its `decision`. MUST throw on an invalid signature, an
 *  unknown/unauthorized key, unavailable verifying material, or a signature that
 *  does not cover `decision` (fail-closed). A field-perfect but unsigned/forged
 *  receipt — including one with a swapped decision — MUST be rejected here. */
export interface AckReceiptVerifier {
  verify(receipt: AckReceipt, record: OutboxRecord<unknown>): Promise<void>;
}
/** Transport delivers a record and returns the receiver's signed decision
 *  receipt. A throw leaves the row undelivered (retry). The row is NEVER acked
 *  on call-completion alone — only on a verified applied|duplicate-ok decision. */
export interface OutboxTransport {
  deliverAndAwaitAck(record: OutboxRecord<unknown>): Promise<AckReceipt>;
}

/** Decisions that mean the receiver durably owns the record → source may ACK. */
const ACK_DECISIONS: ReadonlySet<ReceiverDecision> = new Set<ReceiverDecision>(['applied', 'duplicate-ok']);
/** Transient rejections → release the lease and retry later (no advance). */
const TRANSIENT_DECISIONS: ReadonlySet<ReceiverDecision> = new Set<ReceiverDecision>(['reject-gap', 'reject-fence']);
/** Terminal divergence → quarantine + halt, never ACK, never drop. */
const TERMINAL_DECISIONS: ReadonlySet<ReceiverDecision> = new Set<ReceiverDecision>(['reject-fork', 'reject-stale', 'reject-unsanitized', 'reject-epoch']);
/** (R4/MED) The full closed set of decisions the source will interpret. A
 *  receipt whose decision is outside this set is rejected fail-closed — an
 *  unknown/forged decision is never silently treated as terminal or acked. */
const KNOWN_DECISIONS: ReadonlySet<ReceiverDecision> = new Set<ReceiverDecision>([...ACK_DECISIONS, ...TRANSIENT_DECISIONS, ...TERMINAL_DECISIONS]);

export interface PgPublisherOptions {
  /** Publisher lease duration in ms; a held-but-idle stream is reclaimable after. */
  leaseMs: number;
}

export interface DrainResult {
  /** rows delivered to the transport this drain */
  published: number;
  /** rows acked (verified applied|duplicate-ok) and removed from the outbox */
  acked: number;
  /** rows parked as terminal divergence (fork/stale/unsanitized/epoch) */
  quarantined: number;
  /** true if the drain stopped on a transient rejection and should be retried */
  retriable: boolean;
}

/**
 * Durable publisher with PER-STREAM ORDERED single-active delivery (H1/H2).
 *
 * A stream is a totally-ordered log, so exactly one publisher may deliver it at
 * a time and it delivers strictly ascending / contiguous. Parallelism is ACROSS
 * streams (distinct lease rows), never within one stream. One drain is:
 *   1) short serializable tx: acquire the per-stream publisher lease (steal only
 *      if expired). If held elsewhere → nothing to do.
 *   2) loop: read the LOWEST undelivered row (acked_at IS NULL AND
 *      quarantined_at IS NULL) under our lease; revalidate + recompute digest;
 *      deliver OUTSIDE any tx and await the signed decision receipt.
 *   3) verify the receipt (crypto + record-bound + covers decision), then act on
 *      the SIGNED decision:
 *        applied|duplicate-ok → short tx: ACK exactly this row (guarded by
 *          unacked + op_digest), assert 1 row, advance to the next.
 *        reject-gap|reject-fence (transient) → STOP, leave unacked, retry later.
 *        reject-* (terminal) → short tx: quarantine this row + record it, STOP.
 *   4) release the lease.
 * Because delivery is lowest-first and only advances on applied|duplicate-ok,
 * the receiver's contiguous cp+1 rule is always satisfied in order — no
 * out-of-order delivery, no gap-induced loss, no ack of a rejected record.
 */
export class PgDurablePublisher<Clean> {
  private readonly leaseMs: number;
  private readonly schema: string;
  constructor(
    private readonly db: PgTransactor,
    private readonly streamId: string,
    private readonly transport: OutboxTransport,
    readonly backpressure: PublisherBackpressure,
    /** (#5) sanitizer to revalidate each DB row before publishing. */
    private readonly sanitizer: Pick<MutationSanitizer<unknown, Clean>, 'assertSanitized'>,
    /** (HIGH2) verifier for the receiver's signed decision receipt — REQUIRED. */
    private readonly ackVerifier: AckReceiptVerifier,
    /** (R8) the schema-readiness capability bound to this db + schema. */
    ready: SchemaReadyToken,
    opts: PgPublisherOptions = { leaseMs: 30_000 },
  ) {
    if (!Number.isSafeInteger(opts.leaseMs) || opts.leaseMs <= 0) throw new ContractValidationError('leaseMs must be a positive safe integer');
    this.schema = requireReady(ready, db);
    this.leaseMs = opts.leaseMs;
  }

  /** Acquire the per-stream lease (steal only if expired). Returns true if held. */
  private async acquireLease(leaseToken: string): Promise<boolean> {
    return this.db.transaction(async (exec) => {
      await enterCriticalTx(exec, this.schema);
      const res = await exec.query(
        `INSERT INTO ha_outbox_publisher_lease (stream_id, lease_token, lease_until)
         VALUES ($1, $2, now() + ($3::text || ' milliseconds')::interval)
         ON CONFLICT (stream_id) DO UPDATE
           SET lease_token = EXCLUDED.lease_token, lease_until = EXCLUDED.lease_until
           WHERE ha_outbox_publisher_lease.lease_until IS NULL OR ha_outbox_publisher_lease.lease_until < now()
         RETURNING lease_token`,
        [this.streamId, leaseToken, String(this.leaseMs)],
      );
      return res.rowCount === 1;
    });
  }

  private async releaseLease(leaseToken: string): Promise<void> {
    await this.db.transaction(async (exec) => {
      await enterCriticalTx(exec, this.schema);
      await exec.query('UPDATE ha_outbox_publisher_lease SET lease_token = NULL, lease_until = NULL WHERE stream_id = $1 AND lease_token = $2', [this.streamId, leaseToken]);
    });
  }

  /** Read the lowest deliverable row while re-asserting lease ownership. */
  private async nextDeliverable(leaseToken: string): Promise<Record<string, unknown> | null> {
    return this.db.transaction(async (exec) => {
      await enterCriticalTx(exec, this.schema);
      const lease = (await exec.query('SELECT lease_token FROM ha_outbox_publisher_lease WHERE stream_id = $1 FOR UPDATE', [this.streamId])).rows;
      if (!lease.length || lease[0].lease_token !== leaseToken) throw new ContractValidationError('publisher lease lost — aborting drain');
      const rows = (await exec.query(
        'SELECT source_epoch, sequence, fence_token, op_digest, mutation, quarantined_at FROM ha_outbox_rows WHERE stream_id = $1 AND acked_at IS NULL ORDER BY sequence ASC LIMIT 1',
        [this.streamId],
      )).rows;
      if (!rows[0] || rows[0].quarantined_at != null) return null;
      return {
        source_epoch: rows[0].source_epoch,
        sequence: rows[0].sequence,
        fence_token: rows[0].fence_token,
        op_digest: rows[0].op_digest,
        mutation: rows[0].mutation,
      };
    });
  }

  private async quarantineRecord(
    leaseToken: string,
    sourceEpoch: string,
    sequence: number,
    storedDigest: string,
    decision: string,
  ): Promise<void> {
    await this.db.transaction(async (exec) => {
      await enterCriticalTx(exec, this.schema);
      const lease = (await exec.query('SELECT lease_token FROM ha_outbox_publisher_lease WHERE stream_id = $1 FOR UPDATE', [this.streamId])).rows;
      if (!lease.length || lease[0].lease_token !== leaseToken) throw new ContractValidationError('publisher lease lost — not quarantining');
      const ins = await exec.query(
        `INSERT INTO ha_outbox_quarantine (stream_id, source_epoch, sequence, op_digest, decision)
         VALUES ($1,$2,$3,$4,$5) ON CONFLICT (stream_id, source_epoch, sequence) DO NOTHING`,
        [this.streamId, sourceEpoch, sequence, storedDigest, decision],
      );
      if (ins.rowCount === 0) {
        const ex = (await exec.query('SELECT op_digest, decision FROM ha_outbox_quarantine WHERE stream_id = $1 AND source_epoch = $2 AND sequence = $3 FOR UPDATE', [this.streamId, sourceEpoch, sequence])).rows;
        if (!ex.length) throw new ContractValidationError('quarantine conflict without an existing row');
        if (!digestEquals(String(ex[0].op_digest), storedDigest) || String(ex[0].decision) !== decision) {
          throw new ContractValidationError('quarantine record conflict: existing digest/decision differ from this record');
        }
      } else if (ins.rowCount !== 1) {
        throw new ContractValidationError('quarantine insert affected unexpected row count');
      }
      const mark = await exec.query(
        'UPDATE ha_outbox_rows SET quarantined_at = now() WHERE stream_id = $1 AND source_epoch = $2 AND sequence = $3 AND acked_at IS NULL AND quarantined_at IS NULL',
        [this.streamId, sourceEpoch, sequence],
      );
      affectedOne(mark, 'quarantine mark');
    });
  }

  async drainOnce(): Promise<DrainResult> {
    const leaseToken = randomUUID();
    if (!(await this.acquireLease(leaseToken))) return { published: 0, acked: 0, quarantined: 0, retriable: true };
    let published = 0, acked = 0, quarantined = 0, retriable = false;
    try {
      for (;;) {
        const r = await this.nextDeliverable(leaseToken);
        if (!r) break;
        // Snapshot the complete database row ONCE before validating it. Reading
        // a hostile/proxied mutation for digest verification and then again for
        // delivery would permit two different payloads across that boundary.
        const row = snapshotJson(r, 'outbox database row');
        assertExactOwnKeys(row, ['source_epoch', 'sequence', 'fence_token', 'op_digest', 'mutation'], 'outbox database row');
        const record = snapshotRecord<Clean>({
          contractVersion: '1',
          streamId: this.streamId,
          sourceEpoch: String(row.source_epoch),
          sequence: safeSeq(row.sequence, 'row.sequence'),
          fenceToken: String(row.fence_token),
          opDigest: String(row.op_digest),
          mutation: row.mutation as SanitizedMutation<Clean>,
        });
        const { sourceEpoch, sequence, opDigest: storedDigest, mutation } = record;
        // (#5) fail closed on a corrupted/tampered stored row.
        this.sanitizer.assertSanitized(mutation);
        const recomputed = canonicalOpDigest<Clean>({ streamId: record.streamId, sourceEpoch, sequence, fenceToken: record.fenceToken, mutation });
        if (!digestEquals(recomputed, storedDigest)) throw new ContractValidationError(`corrupted outbox row: digest mismatch at ${this.streamId}/${sourceEpoch}/${sequence}`);

        // deliver OUTSIDE any tx — no DB lock is held across this network call.
        let delivered: AckReceipt;
        try {
          delivered = await this.transport.deliverAndAwaitAck(record);
        } catch (error) {
          if (error && typeof error === 'object'
            && (error as { retriable?: unknown }).retriable === false) {
            await this.quarantineRecord(
              leaseToken, sourceEpoch, sequence, storedDigest,
              'reject-transport-terminal',
            );
            quarantined++;
            break;
          }
          throw error;
        }
        const receipt = snapshotAckReceipt(delivered);
        published++;
        // (HIGH2) verify signature (must cover the decision) came from the authorized receiver…
        await this.ackVerifier.verify(receipt, record); // throw → not acked
        // …AND the receipt is record-bound (echo check on top of the signature).
        if (receipt.streamId !== this.streamId || receipt.sourceEpoch !== sourceEpoch || receipt.sequence !== sequence || !digestEquals(receipt.opDigest, storedDigest)) {
          throw new ContractValidationError('ACK receipt does not match the delivered record — not acking');
        }
        // (R4/MED) closed-set decision: an unknown/forged decision is fail-closed,
        // never silently treated as terminal (or acked).
        if (!KNOWN_DECISIONS.has(receipt.decision)) throw new ContractValidationError(`unknown receiver decision: ${String(receipt.decision)}`);

        if (ACK_DECISIONS.has(receipt.decision)) {
          // (H1) durable ownership → ACK exactly this row, then advance.
          await this.db.transaction(async (exec) => {
            await enterCriticalTx(exec, this.schema);
            const lease = (await exec.query('SELECT lease_token FROM ha_outbox_publisher_lease WHERE stream_id = $1 FOR UPDATE', [this.streamId])).rows;
            if (!lease.length || lease[0].lease_token !== leaseToken) throw new ContractValidationError('publisher lease lost — not acking');
            const res = await exec.query(
              `UPDATE ha_outbox_rows SET published_at = now(), acked_at = now()
               WHERE stream_id = $1 AND source_epoch = $2 AND sequence = $3 AND acked_at IS NULL AND quarantined_at IS NULL AND op_digest = $4`,
              [this.streamId, sourceEpoch, sequence, storedDigest],
            );
            affectedOne(res, 'publisher ack');
          });
          acked++;
          continue;
        }
        if (TRANSIENT_DECISIONS.has(receipt.decision)) {
          // (H1) transient NACK → stop; leave the row for a later retry. Never advance.
          retriable = true;
          break;
        }
        // (H1) terminal NACK → quarantine + halt. Never ACK, never drop.
        await this.quarantineRecord(
          leaseToken, sourceEpoch, sequence, storedDigest, receipt.decision,
        );
        quarantined++;
        break; // divergence on an ordered stream → halt the drain
      }
    } finally {
      await this.releaseLease(leaseToken);
    }
    return { published, acked, quarantined, retriable };
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
  private readonly schema: string;
  constructor(
    /** (R9) the receiver OWNS its transactor; the readiness token must be bound to
     *  it. verifyAndApplyDelivered opens the tx here, so a foreign executor can
     *  never be injected. */
    private readonly db: PgTransactor,
    private readonly streamId: string,
    sanitizer: Pick<MutationSanitizer<unknown, Clean>, 'assertSanitized'>,
    private readonly applier: MutationApplier<Clean>,
    ready: SchemaReadyToken,
    epochAuthorizer: EpochTransitionAuthorizer = { async authorizeTransition() { throw new ContractValidationError('epoch transition not authorized in this slice'); } },
    scopeDeadlineMs: number = DEFAULT_SCOPE_DEADLINE_MS,
  ) { this.schema = requireReady(ready, db); this.sanitizer = sanitizer; this.epochAuthorizer = epochAuthorizer; this.scopeDeadlineMs = validateDeadlineMs(scopeDeadlineMs, 'scopeDeadlineMs'); }
  private readonly scopeDeadlineMs: number;

  /** (R9) The safe public entry: opens the receiver's OWN serializable tx on its
   *  OWN (token-bound) transactor and applies. No external tx/executor can be
   *  injected, so a record can never be applied against a foreign database.
   *  (R13) deadline-bounded + abort-signalled over the whole tx. */
  async verifyAndApplyDelivered(record: OutboxRecord<Clean>): Promise<ReceiverDecision> {
    const captured = snapshotRecord(record);
    return runScoped(this.scopeDeadlineMs, (signal) => this.db.transaction((exec) => withBoundTx(exec, this.db, this.schema, (tx) => this.verifyAndApplyInTx(tx, captured)), { signal }));
  }

  async verifyAndApplyInTx(tx: PgTx, record: OutboxRecord<Clean>): Promise<ReceiverDecision> {
    // (R9/R10/HIGH) reject BEFORE any query: the tx must be bound to THIS
    // receiver's exact transactor + schema AND still be active (not a handle
    // retained past its transaction). A foreign-db, wrong-schema, or stale tx is
    // rejected up front, closing the A-token/B-executor and use-after-tx gaps.
    const exec = execOfBound(tx, this.db, this.schema);
    record = snapshotRecord(record);
    await enterCriticalTx(exec, this.schema);
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
  private readonly schema: string;
  constructor(private readonly db: PgTransactor, ready: SchemaReadyToken) { this.schema = requireReady(ready, db); }
  async acquire(streamId: string): Promise<FenceToken> {
    return this.db.transaction(async (exec) => {
      await enterCriticalTx(exec, this.schema);
      const res = await exec.query(
        `INSERT INTO ha_outbox_fence (stream_id, fence_token) VALUES ($1, 1)
         ON CONFLICT (stream_id) DO UPDATE SET fence_token = ha_outbox_fence.fence_token + 1
         RETURNING fence_token`, [streamId]);
      affectedOne(res, 'promotion fence acquire');
      return BigInt(String(res.rows[0].fence_token));
    });
  }
  async current(streamId: string): Promise<FenceToken> {
    const rows = (await this.db.transaction(async (exec) => {
      await enterCriticalTx(exec, this.schema);
      return exec.query('SELECT fence_token FROM ha_outbox_fence WHERE stream_id = $1', [streamId]);
    })).rows;
    return rows.length ? BigInt(String(rows[0].fence_token)) : 0n;
  }
}
