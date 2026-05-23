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
import { readFileSync, existsSync } from 'node:fs';
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
} from '../packages/server/src/index.ts';
import type {
  BPCRequestData,
  PairRegistration,
  RotationRequest,
  AdminAuthConfig,
} from '../packages/server/src/index.ts';

const PORT        = 3100;
const DEMO_DIR    = dirname(fileURLToPath(import.meta.url));
const ADMIN_TOKEN = process.env['BPC_ADMIN_TOKEN'] ?? 'demo-admin-token';

const ADMIN_AUTH: AdminAuthConfig = { bearerToken: ADMIN_TOKEN };

const ipRateLimiter   = new MemoryRateLimiter(200, 60_000);
const pairRateLimiter = new MemoryRateLimiter(100, 60_000);

const { registry, nonceStore, anomaly } = createBPCServer();
const auditLog = new MemoryAuditLog(10_000);

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
      if (path.startsWith('/bpc/audit/')) {
        json(res, 200, { entries: await auditLog.query(path.split('/')[3]) });
        return;
      }
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
