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
 * STARTUP CONTRACT: callers MUST invoke `assertSchemaReady(db, schema)` at
 * startup (full manifest attestation + version, in the pinned schema) before
 * constructing/using these classes, and pass the SAME `schema` to every
 * constructor. Direct construction does NOT itself attest — there is no
 * constructor-level unforgeable readiness token in this slice (a possible
 * hardening), so a caller that skips the startup gate can operate against an
 * un-attested schema. This is a documented boundary, not a silent gap; #16 open.
 */
import { createHash, randomUUID, timingSafeEqual } from 'node:crypto';
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

/** A validated PostgreSQL schema identifier (lowercase-anchored, no injection). */
function assertSchemaIdentifier(schema: string): void {
  if (!/^[A-Za-z_][A-Za-z0-9_$]{0,62}$/.test(schema)) throw new ContractValidationError(`invalid schema identifier: ${schema}`);
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
  await exec.query('SELECT set_config($1, $2, true)', ['search_path', schema]);
  const cur = (await exec.query('SELECT current_schema() AS s')).rows[0]?.s;
  if (cur !== schema) throw new ContractValidationError(`schema context mismatch: current_schema=${String(cur)} pinned=${schema}`);
}

/** Enter a critical tx: SERIALIZABLE + pinned schema identity, together. */
async function enterCriticalTx(exec: PgExecutor, schema: string): Promise<void> {
  await assertSerializable(exec);
  await pinSchema(exec, schema);
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

/** Schema version this build provisions/expects. Bump on any DDL change;
 *  `assertSchemaVersion` fails closed on drift so a stale migration cannot be
 *  used with newer code. */
export const HA_OUTBOX_SCHEMA_VERSION = 2 as const;

// Contract fence bound: a fence token is an integer with at most 39 digits
// (FENCE_TOKEN_PATTERN in the contract), i.e. strictly < 10^39. The DDL enforces
// the SAME bound plus integrality (scale 0) so a fractional or oversized value
// cannot be persisted.
const FENCE_MAX_EXCLUSIVE = '1e39';

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
export const HA_OUTBOX_PG_SCHEMA = `
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
-- NOTE: the DDL NEVER stamps the version. Stamping happens only through
-- provisionSchemaVersion() / migrateSchemaToCurrent(), each of which runs a full
-- catalog attestation (attestSchema) in the SAME serializable tx first, so a
-- malformed/partial/foreign-schema layout can never be labelled a valid version.
`;

/** Tables that make up the HA-outbox schema (attestation scope). */
const HA_OUTBOX_TABLES = [
  'ha_outbox_meta', 'ha_outbox_fence', 'ha_outbox_source_checkpoint',
  'ha_outbox_receiver_checkpoint', 'ha_outbox_rows', 'ha_outbox_publisher_lease',
  'ha_outbox_quarantine', 'ha_outbox_applied',
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
export const HA_OUTBOX_SCHEMA_MANIFEST = 'ded9abb5f0c381115754bcbd676a12e27d2f8c3b5456465e76d394c00e893de3';

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
 * TEST-ONLY factory: mint a readiness token WITHOUT a live attestation, for
 * hermetic unit tests that use an in-memory fake transactor. Never use in
 * production — it bypasses the attestation the real gate performs.
 */
export function __unsafeMintReadyTokenForTests(db: PgTransactor, schema: string): SchemaReadyToken {
  assertSchemaIdentifier(schema);
  return mintReadyToken({ db, schema, manifest: HA_OUTBOX_SCHEMA_MANIFEST, version: HA_OUTBOX_SCHEMA_VERSION });
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
  private readonly schema: string;
  constructor(private readonly db: PgTransactor, ready: SchemaReadyToken, private readonly opts: PgOutboxOptions<Raw, Clean>) {
    if (!Number.isSafeInteger(opts.maxPendingRows) || opts.maxPendingRows <= 0) {
      throw new ContractValidationError('maxPendingRows must be a positive safe integer');
    }
    this.schema = requireReady(ready, db); // (R8) reject a forged/foreign-db token
    this.sanitizer = opts.sanitizer;
  }

  /** Open a durable tx and run `fn` with the bound handle. The caller performs
   *  its authoritative mutation and `appendInTx` inside `fn`; both commit atomically. */
  async withOutboxTx<T>(fn: (tx: PgTx, exec: PgExecutor) => Promise<T>): Promise<T> {
    return this.db.transaction(async (exec) => {
      await enterCriticalTx(exec, this.schema);
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
        'SELECT source_epoch, sequence, fence_token, op_digest, mutation FROM ha_outbox_rows WHERE stream_id = $1 AND acked_at IS NULL AND quarantined_at IS NULL ORDER BY sequence ASC LIMIT 1',
        [this.streamId],
      )).rows;
      return rows[0] ?? null;
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
        const sourceEpoch = String(r.source_epoch);
        const sequence = safeSeq(r.sequence, 'row.sequence');
        const storedDigest = String(r.op_digest);
        const mutation = r.mutation as SanitizedMutation<Clean>;
        // (#5) fail closed on a corrupted/tampered stored row.
        this.sanitizer.assertSanitized(mutation);
        const recomputed = canonicalOpDigest<Clean>({ streamId: this.streamId, sourceEpoch, sequence, fenceToken: String(r.fence_token), mutation });
        if (!digestEquals(recomputed, storedDigest)) throw new ContractValidationError(`corrupted outbox row: digest mismatch at ${this.streamId}/${sourceEpoch}/${sequence}`);

        const record: OutboxRecord<unknown> = { contractVersion: '1', streamId: this.streamId, sourceEpoch, sequence, fenceToken: String(r.fence_token), opDigest: storedDigest, mutation };
        // deliver OUTSIDE any tx — no DB lock is held across this network call.
        const receipt = await this.transport.deliverAndAwaitAck(record); // throw → row stays, retried
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
        await this.db.transaction(async (exec) => {
          await enterCriticalTx(exec, this.schema);
          const lease = (await exec.query('SELECT lease_token FROM ha_outbox_publisher_lease WHERE stream_id = $1 FOR UPDATE', [this.streamId])).rows;
          if (!lease.length || lease[0].lease_token !== leaseToken) throw new ContractValidationError('publisher lease lost — not quarantining');
          const ins = await exec.query(
            `INSERT INTO ha_outbox_quarantine (stream_id, source_epoch, sequence, op_digest, decision)
             VALUES ($1,$2,$3,$4,$5) ON CONFLICT (stream_id, source_epoch, sequence) DO NOTHING`,
            [this.streamId, sourceEpoch, sequence, storedDigest, receipt.decision],
          );
          if (ins.rowCount === 0) {
            // (R5/HIGH2) a preexisting quarantine row must EXACTLY match this record's
            // digest + decision — a planted/lying row cannot stand in for real evidence.
            const ex = (await exec.query('SELECT op_digest, decision FROM ha_outbox_quarantine WHERE stream_id = $1 AND source_epoch = $2 AND sequence = $3 FOR UPDATE', [this.streamId, sourceEpoch, sequence])).rows;
            if (!ex.length) throw new ContractValidationError('quarantine conflict without an existing row');
            if (!digestEquals(String(ex[0].op_digest), storedDigest) || String(ex[0].decision) !== receipt.decision) {
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
    private readonly streamId: string,
    sanitizer: Pick<MutationSanitizer<unknown, Clean>, 'assertSanitized'>,
    private readonly applier: MutationApplier<Clean>,
    /** (R8) schema-readiness capability. The receiver runs inside the caller's
     *  bound tx (no own transactor), so only the token brand + schema bind here;
     *  the per-tx schema pin in verifyAndApplyInTx is the operational enforcement. */
    ready: SchemaReadyToken,
    epochAuthorizer: EpochTransitionAuthorizer = { async authorizeTransition() { throw new ContractValidationError('epoch transition not authorized in this slice'); } },
  ) { this.schema = requireReady(ready); this.sanitizer = sanitizer; this.epochAuthorizer = epochAuthorizer; }

  async verifyAndApplyInTx(tx: PgTx, record: OutboxRecord<Clean>): Promise<ReceiverDecision> {
    const exec = execOf(tx);
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
