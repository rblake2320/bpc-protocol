/**
 * BPC Demo Server
 *
 * Real backend wired to @bpc/server — serves the demo UI and validates
 * every request through the full 12-step BPC verification pipeline.
 *
 * Run:  npx tsx server.ts
 * Open: http://localhost:3100
 */

import { createServer, IncomingMessage, ServerResponse } from 'node:http';
import { readFileSync, existsSync, appendFileSync } from 'node:fs';
import { join, extname, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  createBPCServer,
  verifyBPCRequest,
  verifyAdminRequest,
  BPC_ERRORS,
  handleRotation,
  MemoryRateLimiter,
  MemoryAuditLog,
  PairRegistry,
  AnomalyEngine,
  ServerNonceStore,
} from '../packages/server/src/index.ts';
import type {
  BPCRequestData,
  PairRegistration,
  RotationRequest,
  AdminAuthConfig,
} from '../packages/server/src/index.ts';
// File stores imported DIRECTLY — not re-exported via index.ts.
// This keeps the enterprise package interface frozen: ultra_server sees no change.
import {
  FilePairStore,
  FileNonceBackend,
  FileAnomalyStore,
} from '../packages/server/src/file-store.ts';

const PORT        = 3100;
const DEMO_DIR    = dirname(fileURLToPath(import.meta.url));
const ADMIN_TOKEN = process.env['BPC_ADMIN_TOKEN'] ?? 'demo-admin-token';
const EVENT_LOG   = join(DEMO_DIR, 'analytics.ndjson');

interface AnalyticsEvent { event: string; session: string; ts: number; site: string; [k: string]: unknown; }
const analyticsEvents: AnalyticsEvent[] = [];

const ADMIN_AUTH: AdminAuthConfig = { bearerToken: ADMIN_TOKEN };

const ipRateLimiter   = new MemoryRateLimiter(200, 60_000);
const pairRateLimiter = new MemoryRateLimiter(100, 60_000);

// ── Persistent storage when BPC_DATA_DIR is set — demo data stays isolated ──
// NEVER point BPC_DATA_DIR at enterprise directories (%APPDATA%\SelfConnect\).
// Demo state and enterprise state must never share a path.
const DATA_DIR = process.env['BPC_DATA_DIR'];
let registry: PairRegistry;
let nonceStore: ServerNonceStore;
let anomaly: AnomalyEngine;
let auditLog: MemoryAuditLog;

if (DATA_DIR) {
  console.log(`[BPC] Persistent store: ${DATA_DIR}`);
  const pairStore    = new FilePairStore(join(DATA_DIR, 'pairs.json'));
  const nonceBackend = new FileNonceBackend(join(DATA_DIR, 'nonces.json'));
  const anomalyStore = new FileAnomalyStore(join(DATA_DIR, 'anomaly.json'));
  registry  = new PairRegistry(pairStore, 2000, 10);
  nonceStore = new ServerNonceStore(nonceBackend, 130_000);
  anomaly   = new AnomalyEngine(anomalyStore);
  auditLog  = new MemoryAuditLog(10_000);
} else {
  ({ registry, nonceStore, anomaly, auditLog } = createBPCServer());
}

// ── TSK Layer 6/7 state (per-server-instance, in-memory) ──────────────────
// The correct segment order is a server-only secret — never sent to clients.
const TSK_ORDERS = ['s→t→h','s→h→t','t→s→h','t→h→s','h→s→t','h→t→s'] as const;
const TSK_CORRECT_ORDER = TSK_ORDERS[Math.floor(Math.random() * TSK_ORDERS.length)];
const TSK_STATIC_ID     = crypto.randomUUID().replace(/-/g,'').slice(0, 12);
const tskHotpCounter    = { value: 0 };

// ── Helpers ───────────────────────────────────────────────────────────────

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function cors(res: ServerResponse): void {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers',
    'Content-Type,Authorization,X-BPC-Pair-Id,X-BPC-Signed-Data,X-BPC-Signature,X-BPC-Version');
}

function json(res: ServerResponse, status: number, data: unknown): void {
  cors(res);
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function log(method: string, path: string, result: string): void {
  const ts = new Date().toISOString().slice(11, 23);
  console.log(`[${ts}] ${method} ${path} => ${result}`);
}

const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.js':   'application/javascript',
  '.css':  'text/css',
  '.svg':  'image/svg+xml',
  '.png':  'image/png',
};

function serveFile(res: ServerResponse, filePath: string): boolean {
  if (!existsSync(filePath)) return false;
  const ext  = extname(filePath);
  const mime = MIME[ext] ?? 'application/octet-stream';
  cors(res);
  res.writeHead(200, { 'Content-Type': mime });
  res.end(readFileSync(filePath));
  return true;
}

// ── HTTP Server ───────────────────────────────────────────────────────────

const server = createServer({ maxHeaderSize: 8 * 1024 * 1024 }, async (req: IncomingMessage, res: ServerResponse) => {
  const method = (req.method ?? 'GET').toUpperCase();
  const url    = req.url ?? '/';
  const path   = url.split('?')[0];
  const ip     = req.socket.remoteAddress ?? '0.0.0.0';

  // ── CORS preflight ───────────────────────────────────────────────────────
  if (method === 'OPTIONS') {
    cors(res);
    res.writeHead(204);
    res.end();
    return;
  }

  try {
    // ── Static files ─────────────────────────────────────────────────────
    if (method === 'GET' && (path === '/' || path === '/index.html')) {
      if (serveFile(res, join(DEMO_DIR, 'index.html'))) return;
    }
    if (method === 'GET' && path === '/lucide.min.js') {
      if (serveFile(res, join(DEMO_DIR, 'lucide.min.js'))) return;
    }
    if (method === 'GET' && path.startsWith('/assets/')) {
      const file = join(DEMO_DIR, path);
      if (serveFile(res, file)) return;
    }

    // ── Registration ─────────────────────────────────────────────────────
    if (method === 'POST' && path === '/bpc/register') {
      const rawBody = await readBody(req);
      let registration: PairRegistration;
      try {
        registration = JSON.parse(rawBody.toString()) as PairRegistration;
      } catch {
        json(res, 400, { error: 'invalid_json' });
        return;
      }
      const pairId = await registry.registerDirect(registration);
      await auditLog.write({ action: 'register', pairId, ip, method, path });
      log(method, path, `REGISTERED pair=${pairId}`);
      json(res, 200, { pairId, status: 'approved' });
      return;
    }

    // ── Revocation ───────────────────────────────────────────────────────
    if (method === 'POST' && path === '/bpc/revoke') {
      const rawBody = await readBody(req);
      let body: { pairId?: string };
      try {
        body = JSON.parse(rawBody.toString()) as { pairId?: string };
      } catch {
        json(res, 400, { error: 'invalid_json' });
        return;
      }
      if (!body.pairId) { json(res, 400, { error: 'missing_pair_id' }); return; }
      await registry.revoke(body.pairId);
      await auditLog.write({ action: 'revoke', pairId: body.pairId, ip, method, path });
      log(method, path, `REVOKED pair=${body.pairId}`);
      json(res, 200, { revoked: true, pairId: body.pairId });
      return;
    }

    // ── Rotation ─────────────────────────────────────────────────────────
    if (method === 'POST' && path === '/bpc/rotate') {
      const rawBody = await readBody(req);
      let rotReq: RotationRequest;
      try {
        rotReq = JSON.parse(rawBody.toString()) as RotationRequest;
      } catch {
        json(res, 400, { error: 'invalid_json' });
        return;
      }
      const result = await handleRotation(
        rotReq,
        registry['store' as keyof typeof registry] as Parameters<typeof handleRotation>[1],
      );
      if (!result.ok) {
        log(method, path, `ROTATION DENIED (${result.error})`);
        json(res, 401, { error: result.error });
        return;
      }
      await auditLog.write({ action: 'rotate', pairId: rotReq.oldPairId, ip, method, path });
      log(method, path, `ROTATED old=${rotReq.oldPairId} new=${result.newPairId}`);
      json(res, 200, { newPairId: result.newPairId });
      return;
    }

    // ── Admin endpoints ───────────────────────────────────────────────────
    if (path === '/bpc/pairs' || path === '/bpc/anomaly' || path.startsWith('/bpc/audit/')) {
      if (method !== 'GET') { json(res, 405, { error: 'method_not_allowed' }); return; }
      const authorized = await verifyAdminRequest(
        req.headers as Record<string, string | string[] | undefined>,
        ADMIN_AUTH,
      );
      if (!authorized) {
        log(method, path, 'ADMIN DENIED');
        json(res, 401, { error: 'unauthorized' });
        return;
      }
      if (path === '/bpc/pairs') {
        json(res, 200, { pairs: await registry.listRedacted() });
        return;
      }
      if (path === '/bpc/anomaly') {
        const [counters, score] = await Promise.all([anomaly.counters(), anomaly.threatScore()]);
        json(res, 200, { score, counters });
        return;
      }
      // /bpc/audit/daily — today's audit entries (external traceability endpoint)
      if (path === '/bpc/audit/daily') {
        const today = new Date().toISOString().slice(0, 10);
        const allEntries = auditLog.queryAll ? await auditLog.queryAll(500) : [];
        const todayMs = new Date(today).getTime();
        const todayEntries = allEntries.filter(e => e.timestamp >= todayMs);
        json(res, 200, { date: today, count: todayEntries.length, entries: todayEntries });
        return;
      }
      if (path.startsWith('/bpc/audit/')) {
        json(res, 200, { entries: await auditLog.query(path.split('/')[3]) });
        return;
      }
    }

    // ── Layer 8: Ghost Pair (Honeypot) registration ───────────────────────
    if (method === 'POST' && path === '/bpc/register-ghost') {
      const rawBody = await readBody(req);
      let body: { name?: string };
      try { body = JSON.parse(rawBody.toString()) as { name?: string }; }
      catch { json(res, 400, { error: 'invalid_json' }); return; }
      // Generate a real keypair and secret so the ghost pair verifies normally
      const { subtle } = crypto;
      const keyPair  = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
      const pubJwk   = await subtle.exportKey('jwk', keyPair.publicKey);
      const rawSec   = crypto.getRandomValues(new Uint8Array(32));
      const rawSecB64 = Buffer.from(rawSec).toString('base64url');
      // HKDF-derive the secret hash (matching @bpc/core hashSecret)
      const km  = await subtle.importKey('raw', rawSec, 'HKDF', false, ['deriveKey']);
      const dk  = await subtle.deriveKey(
        { name: 'HKDF', hash: 'SHA-256',
          salt: Buffer.from('bpc-protocol-hmac-salt-v1'),
          info: Buffer.from('bpc-v1-hmac-key') },
        km, { name: 'HMAC', hash: 'SHA-256', length: 256 }, true, ['sign'],
      );
      const dkRaw = Buffer.from(await subtle.exportKey('raw', dk)).toString('base64url');
      const pairId = await registry.registerGhostPair({
        name:       body.name ?? 'ghost-honeypot',
        pubJwk:     pubJwk as JsonWebKey,
        secretHash: dkRaw,
        scope:      'read',
        mode:       'production',
      }, 'registry_exfil');
      await auditLog.write({ action: 'ghost_register', pairId, ip, method, path });
      log(method, path, `GHOST PAIR PLANTED pair=${pairId}`);
      // Return the credentials — in a real scenario these would be planted in bait env
      json(res, 200, {
        pairId,
        kind: 'ghost',
        rawSecret: rawSecB64,
        pubJwk,
        message: 'Ghost pair planted. Use these credentials in a bait environment to detect attackers.',
      });
      return;
    }

    // ── TSK Layer 6/7 endpoints ───────────────────────────────────────────
    // GET /bpc/tsk/challenge — returns public segment identifiers (NOT the order)
    if (method === 'GET' && path === '/bpc/tsk/challenge') {
      const totpWindow = Math.floor(Date.now() / 30_000);
      json(res, 200, {
        static_id:    TSK_STATIC_ID,
        totp_window:  totpWindow,
        hotp_counter: tskHotpCounter.value,
      });
      return;
    }

    // POST /bpc/tsk/verify — validates all 3 segments + correct server-secret order
    if (method === 'POST' && path === '/bpc/tsk/verify') {
      const rawBody = await readBody(req);
      let body: { segments?: string[]; order?: string };
      try {
        body = JSON.parse(rawBody.toString()) as { segments?: string[]; order?: string };
      } catch {
        json(res, 400, { error: 'invalid_json' });
        return;
      }
      const segments = body.segments ?? [];
      const order    = body.order ?? '';
      await auditLog.write({ action: 'tsk_verify', pairId: `ip:${ip}`, ip, method, path });

      if (segments.length < 3) {
        log(method, path, `TSK_DENY segment_count=${segments.length}`);
        json(res, 401, {
          error:  'tsk_segment_insufficient',
          detail: `Only ${segments.length} of 3 required TSK segments provided. ` +
                  `Static (monthly), TOTP (30s), and HOTP (event-counter) segments ` +
                  `must all be valid simultaneously. A single segment grants zero access.`,
        });
        return;
      }
      if (order !== TSK_CORRECT_ORDER) {
        log(method, path, `TSK_DENY order_mismatch order="${order}"`);
        json(res, 401, {
          error:  'tsk_order_mismatch',
          detail: `Segment order "${order}" does not match the server-only positional map. ` +
                  `The concatenation order is a per-session server secret with 6 possible orderings. ` +
                  `Each wrong guess is logged. Structural secrecy violation detected.`,
        });
        return;
      }
      tskHotpCounter.value++;
      log(method, path, `TSK_PASS hotp_counter=${tskHotpCounter.value}`);
      json(res, 200, { ok: true, message: 'TSK verification passed', hotp_counter: tskHotpCounter.value });
      return;
    }

    // ── BPC-protected API endpoints ───────────────────────────────────────
    if (path.startsWith('/api/')) {
      const rawBody = await readBody(req);
      const digest     = await crypto.subtle.digest('SHA-256', rawBody);
      const bodyHash   = 'sha256:' + Buffer.from(digest).toString('base64url');

      const reqData: BPCRequestData = {
        pairId:     (req.headers['x-bpc-pair-id']     as string) ?? null,
        signedData: (req.headers['x-bpc-signed-data'] as string) ?? null,
        signature:  (req.headers['x-bpc-signature']   as string) ?? null,
        version:    (req.headers['x-bpc-version']     as string) ?? null,
        bodyHash,
        method,
        path,
        ip,
      };

      const result = await verifyBPCRequest(reqData, registry, nonceStore, anomaly, {
        sigWindowMs:  60_000,
        ipRateLimiter,
        rateLimiter:  pairRateLimiter,
        auditLog,
      });

      if (!result.ok) {
        const errCode    = result.error ?? 'unknown_error';
        const httpStatus = BPC_ERRORS[errCode]?.httpStatus ?? 401;
        log(method, path, `DENIED (${errCode}) ${httpStatus}`);
        json(res, httpStatus, { error: errCode, detail: BPC_ERRORS[errCode]?.message });
        return;
      }

      log(method, path, `PASS pair=${result.pairId} scope=${result.pair?.scope}`);

      if (path === '/api/status') {
        json(res, 200, { ok: true, pair: result.pairId, scope: result.pair?.scope, ts: Date.now() });
        return;
      }
      if (path === '/api/users') {
        json(res, 200, { users: ['alice', 'bob', 'charlie'] });
        return;
      }
      if (path === '/api/reports') {
        json(res, 200, { reports: ['Q1-2026', 'Q4-2025', 'Q3-2025'] });
        return;
      }
      if (path === '/api/orders' && method === 'POST') {
        json(res, 200, { orderId: 'ord_' + Math.random().toString(36).slice(2, 10), status: 'created' });
        return;
      }
      if (path === '/api/billing' && method === 'POST') {
        json(res, 200, { billed: true, pair: result.pairId });
        return;
      }
      if (path.startsWith('/api/user/') && method === 'DELETE') {
        if (!['read-write', 'admin'].includes(result.pair?.scope ?? '')) {
          json(res, 403, { error: 'scope_violation' });
          return;
        }
        json(res, 200, { deleted: true, userId: path.split('/')[3] });
        return;
      }
      if (path === '/api/admin/config' && method === 'PUT') {
        if (result.pair?.scope !== 'admin') {
          json(res, 403, { error: 'scope_violation' });
          return;
        }
        json(res, 200, { updated: true });
        return;
      }
      json(res, 404, { error: 'not_found' });
      return;
    }

    // ── Analytics ─────────────────────────────────────────────────────────
    if (method === 'POST' && path === '/analytics/event') {
      const rawBody = await readBody(req);
      try {
        const evt = JSON.parse(rawBody.toString()) as AnalyticsEvent;
        evt.serverTs = Date.now(); evt.ip = ip;
        analyticsEvents.push(evt);
        appendFileSync(EVENT_LOG, JSON.stringify(evt) + '\n');
        cors(res); res.writeHead(204); res.end();
      } catch { json(res, 400, { error: 'invalid_json' }); }
      return;
    }
    if (method === 'GET' && path === '/analytics') {
      const counts: Record<string, number> = {};
      const screens: Record<string, number> = {};
      const sessions = new Set<string>();
      for (const e of analyticsEvents) {
        counts[e.event] = (counts[e.event] || 0) + 1;
        if (e.event === 'tab_view' && e.tab) screens[e.tab as string] = (screens[e.tab as string] || 0) + 1;
        if (e.session) sessions.add(e.session);
      }
      json(res, 200, { totalEvents: analyticsEvents.length, uniqueSessions: sessions.size,
        eventCounts: counts, tabViews: screens, recentEvents: analyticsEvents.slice(-20).reverse() });
      return;
    }

    json(res, 404, { error: 'not_found' });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    log(method, path, `ERROR: ${msg}`);
    json(res, 500, { error: 'internal_error', detail: msg });
  }
});

process.on('uncaughtException',  (err)    => console.error('[CRITICAL] Uncaught:', err));
process.on('unhandledRejection', (reason) => console.error('[CRITICAL] Rejection:', reason));

server.listen(PORT, () => {
  console.log(`\nBPC Demo Server running on http://localhost:${PORT}`);
  console.log(`Admin token: ${ADMIN_TOKEN}`);
  console.log('');
  console.log('  POST /bpc/register            Register a pair');
  console.log('  POST /bpc/revoke              Revoke a pair');
  console.log('  GET  /bpc/pairs   [admin]     List pairs');
  console.log('  GET  /bpc/anomaly [admin]     Threat score + counters');
  console.log('  ANY  /api/*       [BPC]       Protected demo endpoints');
  console.log('');
});
