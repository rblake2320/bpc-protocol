import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';

import { ContractValidationError, canonicalize } from './ha-outbox-contract.js';
import type { OutboxRecord, ReceiverDecision } from './ha-outbox-contract.js';
import type {
  AckReceipt,
  AckReceiptVerifier,
  OutboxTransport,
  PgExecutor,
  PgTransactor,
} from './ha-outbox-pg.js';

/**
 * Authenticated, decision-bound AND request-attempt-bound HTTP transport for the
 * durable pair-outbox publisher -> receiver hop (node A -> node B). It is the ONLY
 * A->B path in the two-node topology, so it is treated as fully untrusted and every
 * boundary is bounded and fail-closed.
 *
 *  - REQUEST auth: HMAC-SHA256 over a length-PREFIXED framing of
 *    (domain, keyId, method, exact-path, timestamp, nonce, sha256(raw body)). The
 *    receiver authorizes the EXACT path, checks freshness, verifies the signature over
 *    the RAW BYTES, and burns a DURABLE single-use nonce, BEFORE parsing/applying.
 *  - RESPONSE binding: the reply envelope is MAC'd (framed) over the fresh request nonce
 *    (challenge) + request body digest + path + canonical receipt, so a prior signed
 *    receipt cannot be replayed for another attempt. Inside sits a decision-bound
 *    `AckReceipt` the publisher verifies separately.
 *  - The WHOLE exchange (connect + bounded streaming body + parse + verify) is raced
 *    against a deadline — a hostile body/verifier that ignores the abort signal cannot
 *    hang the publisher. Errors are classified: auth/protocol/validation are TERMINAL
 *    (retriable:false); network/timeout/5xx are TRANSIENT (retriable:true). A throw
 *    NEVER fabricates an ack.
 *
 * BOUNDARY: HMAC is the slice-1 mechanism (mTLS is a deployment upgrade). NOT an HA
 * claim; #16 stays OPEN until the full acceptance drill passes.
 */

const HDR = { keyId: 'x-bpc-key-id', ts: 'x-bpc-timestamp', nonce: 'x-bpc-nonce', sig: 'x-bpc-signature' } as const;
const CONTENT_TYPE = 'application/json';
const REQ_DOMAIN = 'BPCv1-req';
const ACK_DOMAIN = 'BPCv1-ack';
const DEFAULT_TIMEOUT_MS = 5_000;
const DEFAULT_FRESHNESS_MS = 30_000;
const DEFAULT_MAX_BODY_BYTES = 64 * 1024;
const DEFAULT_BODY_READ_MS = 10_000;
const DEFAULT_NONCE_RETENTION_MS = 120_000;
const DEFAULT_MAX_CLOCK_SKEW_MS = 5_000;
const DEFAULT_NONCE_SAFETY_MS = 30_000;
const NONCE_RE = /^[A-Za-z0-9_-]{16,128}$/;
const KEY_ID_RE = /^[A-Za-z0-9._-]{1,64}$/;
const RECEIPT_KEYS = ['streamId', 'sourceEpoch', 'sequence', 'opDigest', 'decision', 'receiverId', 'keyId', 'issuedAt', 'signature'] as const;
const RECEIPT_TYPES: Record<(typeof RECEIPT_KEYS)[number], 'string' | 'number'> = {
  streamId: 'string', sourceEpoch: 'string', sequence: 'number', opDigest: 'string', decision: 'string', receiverId: 'string', keyId: 'string', issuedAt: 'string', signature: 'string',
};
const ENVELOPE_KEYS = ['v', 'keyId', 'challenge', 'requestDigest', 'receipt', 'sig'] as const;

const sha256hex = (b: Buffer): string => createHash('sha256').update(b).digest('hex');
const hmac = (secret: Buffer, msg: Buffer): Buffer => createHmac('sha256', secret).update(msg).digest();
const b64u = (b: Buffer): string => b.toString('base64url');
function ctEqualB64u(a: string, expected: Buffer): boolean {
  let got: Buffer;
  try { got = Buffer.from(a, 'base64url'); } catch { return false; }
  return got.length === expected.length && timingSafeEqual(got, expected);
}
function frame(...parts: (string | Buffer)[]): Buffer {
  const bufs: Buffer[] = [];
  for (const p of parts) {
    const b = Buffer.isBuffer(p) ? p : Buffer.from(p, 'utf8');
    const len = Buffer.alloc(4); len.writeUInt32BE(b.length, 0);
    bufs.push(len, b);
  }
  return Buffer.concat(bufs);
}
function toSecret(s: Buffer | string, label: string): Buffer {
  const b = Buffer.isBuffer(s) ? Buffer.from(s) : Buffer.from(String(s), 'utf8');
  if (b.length < 32) throw new ContractValidationError(`${label} must be >= 32 bytes`);
  return b;
}
function posInt(n: number, label: string): number {
  if (!Number.isSafeInteger(n) || n < 1) throw new ContractValidationError(`${label} must be a positive safe integer`);
  return n;
}
function isPlainObject(o: unknown): o is Record<string, unknown> {
  if (o === null || typeof o !== 'object') return false;
  const p = Object.getPrototypeOf(o);
  return p === Object.prototype || p === null;
}
/** exact-key set (no extras, no missing, no symbols). */
function hasExactKeys(o: Record<string, unknown>, keys: readonly string[]): boolean {
  const own = Reflect.ownKeys(o);
  if (own.length !== keys.length || own.some((k) => typeof k === 'symbol')) return false;
  for (const k of keys) if (!Object.prototype.hasOwnProperty.call(o, k)) return false;
  return true;
}
function strictReceipt(o: unknown): AckReceipt {
  if (!isPlainObject(o) || !hasExactKeys(o, RECEIPT_KEYS)) throw new ContractValidationError('receipt has an invalid key set');
  const values: Record<string, unknown> = {};
  for (const k of RECEIPT_KEYS) {
    const descriptor = Object.getOwnPropertyDescriptor(o, k);
    if (!descriptor || !descriptor.enumerable || !('value' in descriptor)
      || typeof descriptor.value !== RECEIPT_TYPES[k]) {
      throw new ContractValidationError(`receipt.${k} must be an enumerable data property of type ${RECEIPT_TYPES[k]}`);
    }
    values[k] = descriptor.value;
  }
  return Object.freeze({
    streamId: values.streamId as string, sourceEpoch: values.sourceEpoch as string,
    sequence: values.sequence as number, opDigest: values.opDigest as string,
    decision: values.decision as ReceiverDecision, receiverId: values.receiverId as string,
    keyId: values.keyId as string, issuedAt: values.issuedAt as string,
    signature: values.signature as string,
  });
}
/** strict application/json (rejects application/jsonjunk); params after ';' allowed. */
function isJsonMime(ct: string | null | undefined): boolean {
  if (!ct) return false;
  return ct.split(';', 1)[0].trim().toLowerCase() === CONTENT_TYPE;
}

// ── durable replay-nonce store ───────────────────────────────────────────────

export interface ReplayNonceStore {
  /** Immutable assurances the receiver uses to prove the store retains a nonce across
   *  the whole acceptance horizon EVEN under worst-case clock drift: a nonce's guaranteed
   *  REAL retention is `retentionMs - 2*maxClockSkewMs` (the DB clock may read late at
   *  insert and early at prune, each within the skew bound). */
  readonly retentionMs: number;
  readonly maxClockSkewMs: number;
  checkAndStore(nonce: string): Promise<boolean>;
}

const DURABLE_NONCE_STORES = new WeakSet<object>();
const SCHEMA_RE = /^[a-z_][a-z0-9_]{0,62}$/;

class MemoryReplayNonceStore implements ReplayNonceStore {
  readonly retentionMs: number;
  readonly maxClockSkewMs = 0; // single in-process clock, no DB/app skew
  private readonly seen = new Map<string, number>();
  constructor(retentionMs = DEFAULT_NONCE_RETENTION_MS, private readonly now: () => number = Date.now) {
    this.retentionMs = posInt(retentionMs, 'retentionMs');
  }
  async checkAndStore(nonce: string): Promise<boolean> {
    const t = this.now();
    for (const [k, exp] of this.seen) if (exp <= t) this.seen.delete(k);
    if (this.seen.has(nonce)) return false;
    this.seen.set(nonce, t + this.retentionMs);
    return true;
  }
}

/** Test-only source import; deliberately omitted from the package entry point. */
export function createMemoryReplayNonceStoreForTests(
  retentionMs = DEFAULT_NONCE_RETENTION_MS,
  now: () => number = Date.now,
): ReplayNonceStore {
  const store = new MemoryReplayNonceStore(retentionMs, now);
  DURABLE_NONCE_STORES.add(store);
  return store;
}

export const BPC_TRANSPORT_NONCE_SCHEMA = `
CREATE TABLE IF NOT EXISTS bpc_transport_nonce (
  nonce      text        PRIMARY KEY,
  expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS bpc_transport_nonce_expiry ON bpc_transport_nonce (expires_at);
`.trim();

export interface PgReplayNonceStoreOptions {
  retentionMs?: number;
  maxClockSkewMs?: number;
  now?: () => number;
}

/** Durable replay-nonce store. DB-authored expiry (`now() + retention`, never a sender
 *  timestamp), same-clock pruning, asserted DB/app skew (fail closed), atomic insert. */
export class PgReplayNonceStore implements ReplayNonceStore {
  readonly retentionMs: number;
  readonly maxClockSkewMs: number;
  private readonly now: () => number;
  private constructor(
    private readonly db: PgTransactor,
    private readonly schema: string,
    opts: PgReplayNonceStoreOptions = {},
  ) {
    this.retentionMs = posInt(opts.retentionMs ?? DEFAULT_NONCE_RETENTION_MS, 'retentionMs');
    this.maxClockSkewMs = posInt(opts.maxClockSkewMs ?? DEFAULT_MAX_CLOCK_SKEW_MS, 'maxClockSkewMs');
    this.now = opts.now ?? Date.now;
  }

  static async open(
    db: PgTransactor,
    schema: string,
    opts: PgReplayNonceStoreOptions = {},
  ): Promise<PgReplayNonceStore> {
    if (!db || typeof db.transaction !== 'function') {
      throw new ContractValidationError('replay-nonce store requires a PostgreSQL transactor');
    }
    if (!SCHEMA_RE.test(schema)) {
      throw new ContractValidationError('replay-nonce schema must be a lowercase unquoted identifier');
    }
    const store = new PgReplayNonceStore(db, schema, opts);
    await db.transaction(async (exec) => {
      await store.enterAndAttest(exec);
    });
    DURABLE_NONCE_STORES.add(store);
    return store;
  }

  private async enterAndAttest(exec: PgExecutor): Promise<void> {
    const isolation = String((await exec.query('SHOW transaction_isolation')).rows[0]?.transaction_isolation);
    if (isolation.toLowerCase() !== 'serializable') {
      throw new ContractValidationError('replay-nonce transaction must be SERIALIZABLE');
    }
    await exec.query("SELECT pg_catalog.set_config('search_path', $1, true)", [this.schema]);
    const current = String((await exec.query('SELECT pg_catalog.current_schema() AS schema')).rows[0]?.schema);
    if (current !== this.schema) throw new ContractValidationError('replay-nonce schema context mismatch');
    // Hold a table lock through catalog attestation and nonce insertion. Without
    // this, concurrent DDL can commit after the catalog reads but before DML;
    // PostgreSQL SERIALIZABLE snapshots do not make catalog DDL atomic with DML.
    await exec.query('LOCK TABLE bpc_transport_nonce IN SHARE ROW EXCLUSIVE MODE');
    const table = (await exec.query(
      `SELECT c.relkind, c.relpersistence, c.relrowsecurity, c.relforcerowsecurity
         FROM pg_catalog.pg_class c
         JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = $1 AND c.relname = 'bpc_transport_nonce'`,
      [this.schema],
    )).rows;
    if (table.length !== 1 || table[0].relkind !== 'r' || table[0].relpersistence !== 'p'
      || table[0].relrowsecurity !== false || table[0].relforcerowsecurity !== false) {
      throw new ContractValidationError('replay-nonce table attestation failed');
    }
    const columns = (await exec.query(
      `SELECT a.attname, pg_catalog.format_type(a.atttypid, a.atttypmod) AS type,
              a.attnotnull, pg_catalog.pg_get_expr(d.adbin, d.adrelid) AS default_expr
         FROM pg_catalog.pg_attribute a
         JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
         JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
         LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
        WHERE n.nspname = $1 AND c.relname = 'bpc_transport_nonce'
          AND a.attnum > 0 AND NOT a.attisdropped ORDER BY a.attnum`,
      [this.schema],
    )).rows;
    const expected = [
      { attname: 'nonce', type: 'text', attnotnull: true, default_expr: null },
      { attname: 'expires_at', type: 'timestamp with time zone', attnotnull: true, default_expr: null },
    ];
    if (JSON.stringify(columns) !== JSON.stringify(expected)) {
      throw new ContractValidationError('replay-nonce column attestation failed');
    }
    const authority = (await exec.query(
      `SELECT
         (SELECT count(*)::int FROM pg_catalog.pg_constraint x
           WHERE x.conrelid = c.oid AND x.contype = 'p'
             AND pg_catalog.pg_get_constraintdef(x.oid, true) = 'PRIMARY KEY (nonce)') AS primary_keys,
         (SELECT count(*)::int FROM pg_catalog.pg_constraint x
           WHERE x.conrelid = c.oid AND x.contype NOT IN ('p', 'n')) AS unexpected_constraints,
         (SELECT count(*)::int FROM pg_catalog.pg_index x WHERE x.indrelid = c.oid) AS indexes,
         (SELECT count(*)::int FROM pg_catalog.pg_trigger x WHERE x.tgrelid = c.oid AND NOT x.tgisinternal) AS triggers,
         (SELECT count(*)::int FROM pg_catalog.pg_policy x WHERE x.polrelid = c.oid) AS policies
       FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
       WHERE n.nspname=$1 AND c.relname='bpc_transport_nonce'`,
      [this.schema],
    )).rows[0];
    if (!authority || Number(authority.primary_keys) !== 1 || Number(authority.unexpected_constraints) !== 0
      || Number(authority.indexes) !== 2 || Number(authority.triggers) !== 0
      || Number(authority.policies) !== 0) {
      throw new ContractValidationError('replay-nonce authority attestation failed');
    }
    const indexes = (await exec.query(
      `SELECT ci.relname AS name, i.indisprimary, i.indisunique, am.amname AS method,
              pg_catalog.array_to_string(ARRAY(SELECT a.attname FROM unnest(i.indkey) WITH ORDINALITY AS k(attnum, ord)
                    JOIN pg_catalog.pg_attribute a ON a.attrelid=i.indrelid AND a.attnum=k.attnum
                    ORDER BY k.ord), ',') AS keys,
              pg_catalog.pg_get_expr(i.indpred, i.indrelid) AS predicate
         FROM pg_catalog.pg_index i
         JOIN pg_catalog.pg_class t ON t.oid=i.indrelid
         JOIN pg_catalog.pg_namespace n ON n.oid=t.relnamespace
         JOIN pg_catalog.pg_class ci ON ci.oid=i.indexrelid
         JOIN pg_catalog.pg_am am ON am.oid=ci.relam
        WHERE n.nspname=$1 AND t.relname='bpc_transport_nonce' ORDER BY ci.relname`,
      [this.schema],
    )).rows;
    const expectedIndexes = [
      { name: 'bpc_transport_nonce_expiry', indisprimary: false, indisunique: false, method: 'btree', keys: 'expires_at', predicate: null },
      { name: 'bpc_transport_nonce_pkey', indisprimary: true, indisunique: true, method: 'btree', keys: 'nonce', predicate: null },
    ];
    if (JSON.stringify(indexes) !== JSON.stringify(expectedIndexes)) {
      throw new ContractValidationError(
        `replay-nonce index attestation failed: ${JSON.stringify(indexes)}`,
      );
    }
  }

  async checkAndStore(nonce: string): Promise<boolean> {
    return this.db.transaction(async (exec) => {
      await this.enterAndAttest(exec);
      const dbNow = Number((await exec.query("SELECT (extract(epoch from now()) * 1000)::bigint::text AS ms")).rows[0]?.ms);
      const appNow = this.now();
      if (!Number.isSafeInteger(appNow) || !Number.isFinite(dbNow)
        || Math.abs(dbNow - appNow) > this.maxClockSkewMs) {
        throw new ContractValidationError('replay-nonce store: DB/app clock skew exceeds the allowed bound (fail closed)');
      }
      await exec.query('DELETE FROM bpc_transport_nonce WHERE expires_at < now()');
      const res = await exec.query(
        "INSERT INTO bpc_transport_nonce (nonce, expires_at) VALUES ($1, now() + ($2 || ' milliseconds')::interval) ON CONFLICT (nonce) DO NOTHING",
        [nonce, String(this.retentionMs)],
      );
      return res.rowCount === 1;
    });
  }
}

// ── client: HttpOutboxTransport ──────────────────────────────────────────────

export interface FetchResponseLike {
  status: number;
  headers: { get(name: string): string | null };
  /** REQUIRED: a web ReadableStream read under a hard cap with cancel. A response with no
   *  stream is refused — there is no unbounded text() fallback (that would buffer first). */
  body: ReadableStream<Uint8Array> | null;
}
export type FetchLike = (
  url: string,
  init: { method: string; headers: Record<string, string>; body: string; signal?: AbortSignal; redirect?: 'manual' | 'error' | 'follow' },
) => Promise<FetchResponseLike>;

export class OutboxTransportError extends Error {
  readonly retriable: boolean;
  constructor(message: string, options?: ErrorOptions & { retriable?: boolean }) {
    super(message, options);
    this.name = 'OutboxTransportError';
    this.retriable = options?.retriable ?? true;
  }
}
/** The only acknowledgement-verifier failure that is safe to retry. */
export class AckVerificationUnavailableError extends Error {
  constructor(message = 'acknowledgement verifier unavailable', options?: ErrorOptions) {
    super(message, options);
    this.name = 'AckVerificationUnavailableError';
  }
}
const terminal = (m: string, cause?: unknown): OutboxTransportError => new OutboxTransportError(m, { retriable: false, cause });
const transient = (m: string, cause?: unknown): OutboxTransportError => new OutboxTransportError(m, { retriable: true, cause });
/** Closed HTTP-status classification. Transient (retry): 5xx, 408 request-timeout,
 *  429 too-many-requests. Terminal (do not retry): 3xx redirect, all other 4xx. */
function classifyStatus(status: number): OutboxTransportError {
  if (status >= 500 || status === 408 || status === 429) return transient(`transport received HTTP ${status}`);
  return terminal(`transport received HTTP ${status}`);
}

export interface HttpOutboxTransportOptions {
  url: string;
  fetch: FetchLike;
  requestKeyId: string;
  requestSecret: Buffer | string;
  /** Resolve a RESPONSE keyId to its secret (or null). Multiple valid keyIds = rotation overlap. */
  resolveResponseKey(keyId: string): Buffer | string | null;
  ackVerifier: AckReceiptVerifier;
  now?: () => number;
  nonce?: () => string;
  timeoutMs?: number;
  maxResponseBytes?: number;
  maxRequestBytes?: number;
}

export class HttpOutboxTransport implements OutboxTransport {
  private readonly url: URL;
  private readonly path: string;
  private readonly reqSecret: Buffer;
  private readonly now: () => number;
  private readonly nonce: () => string;
  private readonly timeoutMs: number;
  private readonly maxResponseBytes: number;
  private readonly maxRequestBytes: number;

  constructor(private readonly opts: HttpOutboxTransportOptions) {
    if (typeof opts.fetch !== 'function') throw new ContractValidationError('fetch is required');
    if (typeof opts.resolveResponseKey !== 'function') throw new ContractValidationError('resolveResponseKey is required');
    if (!KEY_ID_RE.test(opts.requestKeyId)) throw new ContractValidationError('invalid requestKeyId');
    this.url = new URL(opts.url);
    if (this.url.protocol !== 'http:' && this.url.protocol !== 'https:') throw new ContractValidationError('transport url must be http(s)');
    if (this.url.username || this.url.password) throw new ContractValidationError('transport url must not embed credentials');
    if (this.url.hash) throw new ContractValidationError('transport url must not contain a fragment');
    this.path = this.url.pathname + this.url.search;
    this.reqSecret = toSecret(opts.requestSecret, 'requestSecret');
    this.now = opts.now ?? Date.now;
    this.nonce = opts.nonce ?? (() => b64u(randomBytes(24)));
    this.timeoutMs = posInt(opts.timeoutMs ?? DEFAULT_TIMEOUT_MS, 'timeoutMs');
    this.maxResponseBytes = posInt(opts.maxResponseBytes ?? DEFAULT_MAX_BODY_BYTES, 'maxResponseBytes');
    this.maxRequestBytes = posInt(opts.maxRequestBytes ?? DEFAULT_MAX_BODY_BYTES, 'maxRequestBytes');
  }

  async deliverAndAwaitAck(record: OutboxRecord<unknown>): Promise<AckReceipt> {
    const body = canonicalize(record);
    const capturedRecord = Object.freeze(JSON.parse(body)) as OutboxRecord<unknown>;
    const bodyBuf = Buffer.from(body, 'utf8');
    if (bodyBuf.length > this.maxRequestBytes) throw terminal(`request body ${bodyBuf.length}B exceeds maxRequestBytes ${this.maxRequestBytes}B`);
    const nonce = this.nonce();
    if (!NONCE_RE.test(nonce)) throw terminal('nonce generator produced an invalid nonce');
    const tnum = this.now();
    if (!Number.isSafeInteger(tnum)) throw terminal('clock produced a non-integer timestamp');
    const ts = String(tnum);
    const bodyDigest = sha256hex(bodyBuf);
    const controller = new AbortController();
    let timer!: ReturnType<typeof setTimeout>;
    const deadline = new Promise<never>((_, reject) => {
      timer = setTimeout(() => { try { controller.abort(); } catch { /* noop */ } reject(transient(`transport deadline ${this.timeoutMs}ms exceeded`)); }, this.timeoutMs);
    });
    // race the ENTIRE operation against the deadline; swallow any late settlement so a
    // hostile body/verifier that ignores the abort cannot hang or double-reject.
    const work = this.doDeliver(capturedRecord, body, bodyDigest, ts, nonce, controller.signal);
    work.catch(() => { /* swallowed: deadline may have already won */ });
    try {
      return await Promise.race([work, deadline]);
    } finally {
      clearTimeout(timer);
      try { controller.abort(); } catch { /* noop */ }
    }
  }

  private async doDeliver(record: OutboxRecord<unknown>, body: string, bodyDigest: string, ts: string, nonce: string, signal: AbortSignal): Promise<AckReceipt> {
    const sig = b64u(hmac(this.reqSecret, frame(REQ_DOMAIN, this.opts.requestKeyId, 'POST', this.path, ts, nonce, bodyDigest)));
    let res: FetchResponseLike;
    try {
      res = await this.opts.fetch(this.url.toString(), {
        method: 'POST',
        headers: { 'content-type': CONTENT_TYPE, [HDR.keyId]: this.opts.requestKeyId, [HDR.ts]: ts, [HDR.nonce]: nonce, [HDR.sig]: sig },
        body, signal, redirect: 'manual',
      });
    } catch (err) {
      throw err instanceof OutboxTransportError ? err : transient('transport request failed', err);
    }
    if (res.status !== 200) throw classifyStatus(res.status);
    if (!isJsonMime(res.headers.get('content-type'))) throw terminal('transport reply is not application/json');
    const cl = Number(res.headers.get('content-length') ?? 'NaN');
    if (Number.isFinite(cl) && cl > this.maxResponseBytes) throw terminal('transport reply too large');
    const text = await this.readCapped(res, signal);
    return this.verifyEnvelope(text, record, nonce, bodyDigest);
  }

  /** Read the response body under a HARD cap, cancelling the stream at the limit
   *  (Content-Length was only an optimization; a chunked reply has none). */
  private async readCapped(res: FetchResponseLike, signal: AbortSignal): Promise<string> {
    const stream = res.body;
    if (!stream || typeof stream.getReader !== 'function') throw terminal('transport response has no readable body stream');
    const reader = stream.getReader();
    // Explicitly CANCEL the reader on abort/deadline: a hostile/nonconforming reader
    // whose read() never settles would otherwise be left dangling by the outer race.
    const onAbort = () => { reader.cancel(new Error('aborted')).catch(() => { /* swallow late */ }); };
    if (signal.aborted) onAbort(); else signal.addEventListener('abort', onAbort, { once: true });
    const chunks: Buffer[] = [];
    let total = 0;
    try {
      for (;;) {
        if (signal.aborted) throw transient('transport aborted');
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > this.maxResponseBytes) { try { await reader.cancel(); } catch { /* noop */ } throw terminal('transport reply too large'); }
        chunks.push(Buffer.from(value.buffer, value.byteOffset, value.byteLength));
      }
    } finally {
      signal.removeEventListener('abort', onAbort);
      try { reader.releaseLock(); } catch { /* noop */ }
    }
    return Buffer.concat(chunks).toString('utf8');
  }

  private async verifyEnvelope(text: string, record: OutboxRecord<unknown>, sentNonce: string, sentBodyDigest: string): Promise<AckReceipt> {
    let env: unknown;
    try { env = JSON.parse(text); } catch (err) { throw terminal('transport reply is not valid JSON', err); }
    if (!isPlainObject(env) || !hasExactKeys(env, ENVELOPE_KEYS) || env.v !== ACK_DOMAIN
      || typeof env.keyId !== 'string' || typeof env.challenge !== 'string' || typeof env.requestDigest !== 'string' || typeof env.sig !== 'string') {
      throw terminal('transport reply envelope malformed');
    }
    if (env.challenge !== sentNonce || env.requestDigest !== sentBodyDigest) throw terminal('transport reply not bound to this request attempt');
    const respSecretRaw = this.opts.resolveResponseKey(env.keyId);
    if (respSecretRaw === null) throw terminal('transport reply signed under an unknown response key');
    const respSecret = toSecret(respSecretRaw, 'resolved response secret');
    let receipt: AckReceipt;
    try { receipt = strictReceipt(env.receipt); } catch (err) { throw terminal('transport reply receipt malformed', err); }
    const mac = hmac(respSecret, frame(ACK_DOMAIN, env.keyId, env.challenge, env.requestDigest, this.path, canonicalize(receipt)));
    if (!ctEqualB64u(env.sig, mac)) throw terminal('transport reply envelope MAC invalid');
    if (receipt.streamId !== record.streamId || receipt.sourceEpoch !== record.sourceEpoch || receipt.sequence !== record.sequence || receipt.opDigest !== record.opDigest) {
      throw terminal('transport reply does not bind to the delivered record');
    }
    try {
      await this.opts.ackVerifier.verify(receipt, record);
    } catch (err) {
      if (err instanceof AckVerificationUnavailableError) {
        throw transient('transport reply ack verifier unavailable', err);
      }
      throw terminal('transport reply ack signature/authorization invalid', err);
    }
    return receipt;
  }
}

// ── receiver: authenticated ingest handler ───────────────────────────────────

export interface HttpOutboxReceiverOptions {
  expectedPath: string;
  resolveRequestKey(keyId: string): Buffer | string | null;
  responseKeyId: string;
  responseSecret: Buffer | string;
  receive(record: OutboxRecord<unknown>): Promise<AckReceipt>;
  nonceStore: ReplayNonceStore;
  now?: () => number;
  freshnessMs?: number;
  /** Explicit extra margin required on top of the acceptance horizon + skew. */
  nonceSafetyMs?: number;
  maxBodyBytes?: number;
  bodyReadMs?: number;
}

export function createHttpOutboxReceiver(opts: HttpOutboxReceiverOptions): (req: IncomingMessage, res: ServerResponse) => void {
  const now = opts.now ?? Date.now;
  const freshnessMs = posInt(opts.freshnessMs ?? DEFAULT_FRESHNESS_MS, 'freshnessMs');
  const safetyMs = posInt(opts.nonceSafetyMs ?? DEFAULT_NONCE_SAFETY_MS, 'nonceSafetyMs');
  const maxBodyBytes = posInt(opts.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES, 'maxBodyBytes');
  const bodyReadMs = posInt(opts.bodyReadMs ?? DEFAULT_BODY_READ_MS, 'bodyReadMs');
  if (!DURABLE_NONCE_STORES.has(opts.nonceStore as object)) {
    throw new ContractValidationError('nonceStore is not a durable attested replay authority');
  }
  if (typeof opts.expectedPath !== 'string' || !opts.expectedPath.startsWith('/')) throw new ContractValidationError('expectedPath must be an absolute request path');
  if (!KEY_ID_RE.test(opts.responseKeyId)) throw new ContractValidationError('invalid responseKeyId');
  const respSecret = toSecret(opts.responseSecret, 'responseSecret');
  // A nonce's GUARANTEED real retention under worst-case skew is retentionMs - 2*skew. It
  // must cover the full acceptance horizon (a timestamp is acceptable across ±freshness =
  // 2*freshness) plus an explicit safety margin — else a still-acceptable nonce could be
  // pruned and replayed. i.e. retentionMs >= 2*freshness + 2*maxClockSkew + safety.
  const guaranteed = opts.nonceStore.retentionMs - 2 * opts.nonceStore.maxClockSkewMs;
  if (!(guaranteed >= 2 * freshnessMs + safetyMs)) {
    throw new ContractValidationError(`nonce retention too small: guaranteed ${guaranteed}ms (retention ${opts.nonceStore.retentionMs} - 2*skew ${opts.nonceStore.maxClockSkewMs}) must be >= 2*freshness ${2 * freshnessMs} + safety ${safetyMs}`);
  }

  const send = (res: ServerResponse, status: number, obj: unknown): void => {
    const payload = canonicalize(obj);
    res.statusCode = status;
    res.setHeader('content-type', CONTENT_TYPE);
    res.setHeader('content-length', String(Buffer.byteLength(payload, 'utf8')));
    res.end(payload);
  };

  return (req, res) => {
    void (async () => {
      try {
        if (req.method !== 'POST') return send(res, 405, { error: 'method not allowed' });
        if ((req.url ?? '') !== opts.expectedPath) return send(res, 404, { error: 'not found' });
        if (!isJsonMime(req.headers['content-type'])) return send(res, 415, { error: 'unsupported media type' });

        let body: Buffer;
        try { body = await readBodyCapped(req, maxBodyBytes, bodyReadMs); }
        catch (e) { return send(res, e instanceof Error && e.message === 'timeout' ? 408 : 413, { error: 'body read failed' }); }

        const keyId = header(req, HDR.keyId), ts = header(req, HDR.ts), nonce = header(req, HDR.nonce), sig = header(req, HDR.sig);
        if (!keyId || !ts || !nonce || !sig || !KEY_ID_RE.test(keyId) || !NONCE_RE.test(nonce)) return send(res, 401, { error: 'unauthenticated' });
        const secretRaw = opts.resolveRequestKey(keyId);
        if (secretRaw === null) return send(res, 401, { error: 'unknown key' });
        const secretBuf = Buffer.isBuffer(secretRaw) ? Buffer.from(secretRaw) : Buffer.from(String(secretRaw), 'utf8');
        if (secretBuf.length < 32) return send(res, 500, { error: 'ingest failed' }); // misconfigured key, don't leak
        if (!/^(0|[1-9][0-9]{0,15})$/.test(ts)) return send(res, 401, { error: 'stale or invalid timestamp' });
        const tsNum = Number(ts);
        const currentTime = now();
        if (!Number.isSafeInteger(tsNum) || !Number.isSafeInteger(currentTime)
          || Math.abs(currentTime - tsNum) > freshnessMs) {
          return send(res, 401, { error: 'stale or invalid timestamp' });
        }
        const bodyDigest = sha256hex(body);
        const expected = hmac(secretBuf, frame(REQ_DOMAIN, keyId, 'POST', req.url ?? '', ts, nonce, bodyDigest));
        if (!ctEqualB64u(sig, expected)) return send(res, 401, { error: 'bad signature' });
        if (!(await opts.nonceStore.checkAndStore(nonce))) return send(res, 401, { error: 'replay' });

        let parsed: OutboxRecord<unknown>;
        try { parsed = JSON.parse(body.toString('utf8')) as OutboxRecord<unknown>; } catch { return send(res, 400, { error: 'invalid json' }); }
        if (!isPlainObject(parsed)) return send(res, 400, { error: 'invalid record' });

        const receipt = strictReceipt(await opts.receive(parsed));
        const envelopeSig = b64u(hmac(respSecret, frame(ACK_DOMAIN, opts.responseKeyId, nonce, bodyDigest, req.url ?? '', canonicalize(receipt))));
        return send(res, 200, { v: ACK_DOMAIN, keyId: opts.responseKeyId, challenge: nonce, requestDigest: bodyDigest, receipt, sig: envelopeSig });
      } catch {
        try { send(res, 500, { error: 'ingest failed' }); } catch { /* response already gone */ }
      }
    })();
  };
}

function header(req: IncomingMessage, name: string): string | null {
  const v = req.headers[name];
  return typeof v === 'string' ? v : Array.isArray(v) ? (v[0] ?? null) : null;
}
function readBodyCapped(req: IncomingMessage, maxBytes: number, readMs: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    const timer = setTimeout(() => { req.destroy(); reject(new Error('timeout')); }, readMs);
    req.on('data', (c: Buffer) => {
      total += c.length;
      if (total > maxBytes) { clearTimeout(timer); req.destroy(); reject(new Error('too large')); return; }
      chunks.push(c);
    });
    req.on('end', () => { clearTimeout(timer); resolve(Buffer.concat(chunks)); });
    req.on('error', (e) => { clearTimeout(timer); reject(e); });
  });
}
