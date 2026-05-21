/**
 * BPC Full-Stack Example Server — IL4-7 Hardened
 *
 * Security controls demonstrated:
 *  - Admin endpoints (/bpc/pairs, /bpc/anomaly, /bpc/audit) require
 *    Authorization: Bearer <token> (AdminAuthConfig / verifyAdminRequest)
 *  - Dual-track rate limiting:
 *      ipRateLimiter:  200 req/min per IP  (pre-auth, blocks unauthenticated floods)
 *      rateLimiter:    100 req/min per pair (post-auth, per-pair budget)
 *  - Body hash verification on all /api/* routes
 *  - Structured audit logging on every request
 *  - Global unhandled-exception safety net (process never crashes silently)
 */

import { createServer, IncomingMessage, ServerResponse } from 'node:http';
import {
  createBPCServer,
  verifyBPCRequest,
  verifyAdminRequest,
  BPC_ERRORS,
  handleRotation,
  MemoryRateLimiter,
  MemoryAuditLog,
} from '../../packages/server/src/index.ts';
import type {
  BPCRequestData,
  PairRegistration,
  RotationRequest,
  AdminAuthConfig,
} from '../../packages/server/src/index.ts';

const PORT = 3100;

// ── Admin authentication ──────────────────────────────────────────────────────
// In production, load this from a secrets manager (Vault, AWS Secrets Manager,
// GCP Secret Manager, etc.) — never hardcode in source.
// For IL5-7, replace bearerToken with a verifier that validates a JWT or mTLS cert.
const ADMIN_AUTH: AdminAuthConfig = {
  bearerToken: process.env['BPC_ADMIN_TOKEN'] ?? 'change-me-in-production-use-32-random-bytes',
};

// ── Rate limiters ─────────────────────────────────────────────────────────────
// ipRateLimiter: fires BEFORE any BPC header is read — blocks unauthenticated floods.
// rateLimiter:   fires per-pair AFTER pairId is validated — per-client budget.
const ipRateLimiter  = new MemoryRateLimiter(200, 60_000);   // 200 req/min per IP
const pairRateLimiter = new MemoryRateLimiter(100, 60_000);  // 100 req/min per pair

// ── Server instance ───────────────────────────────────────────────────────────
const { registry, nonceStore, anomaly } = createBPCServer();
const auditLog = new MemoryAuditLog(10_000);

// ── Helpers ───────────────────────────────────────────────────────────────────
function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function json(res: ServerResponse, status: number, data: unknown): void {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function log(method: string, path: string, result: string): void {
  const ts = new Date().toISOString().slice(11, 23);
  console.log(`[${ts}] ${method} ${path} => ${result}`);
}

// ── HTTP Server ───────────────────────────────────────────────────────────────
// Raise maxHeaderSize to 8 MB so oversized headers reach our middleware,
// which then rejects them with a proper JSON 400 (not a silent Node 431).
const server = createServer({ maxHeaderSize: 8 * 1024 * 1024 }, async (req: IncomingMessage, res: ServerResponse) => {
  const method = (req.method ?? 'GET').toUpperCase();
  const path = req.url ?? '/';
  const ip = req.socket.remoteAddress ?? '0.0.0.0';

  try {
    // ── Registration endpoint (no BPC required) ──────────────────────────────
    // NOTE: In production, gate this behind your own auth or invite flow.
    // Open registration is only appropriate for development/testing.
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

    // ── Revocation endpoint ──────────────────────────────────────────────────
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

    // ── Rotation endpoint ────────────────────────────────────────────────────
    if (method === 'POST' && path === '/bpc/rotate') {
      const rawBody = await readBody(req);
      let rotReq: RotationRequest;
      try {
        rotReq = JSON.parse(rawBody.toString()) as RotationRequest;
      } catch {
        json(res, 400, { error: 'invalid_json' });
        return;
      }
      const result = await handleRotation(rotReq, registry['store' as keyof typeof registry] as Parameters<typeof handleRotation>[1]);
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

    // ── Admin endpoints — REQUIRE authentication ─────────────────────────────
    // BPC-04 / Chain-3 fix: /bpc/pairs, /bpc/anomaly, /bpc/audit are now
    // protected by AdminAuthConfig. Unauthenticated access returns 401.
    if (method === 'GET' && (path === '/bpc/pairs' || path === '/bpc/anomaly' || path.startsWith('/bpc/audit/'))) {
      const authorized = await verifyAdminRequest(
        req.headers as Record<string, string | string[] | undefined>,
        ADMIN_AUTH,
      );
      if (!authorized) {
        log(method, path, 'ADMIN DENIED (unauthorized)');
        json(res, 401, { error: 'unauthorized' });
        return;
      }

      if (path === '/bpc/pairs') {
        const pairs = await registry.listRedacted();
        json(res, 200, { pairs });
        return;
      }

      if (path === '/bpc/anomaly') {
        const counters = await anomaly.counters();
        const score    = await anomaly.threatScore();
        json(res, 200, { score, counters });
        return;
      }

      if (path.startsWith('/bpc/audit/')) {
        const targetPairId = path.split('/')[3];
        const entries = await auditLog.query(targetPairId);
        json(res, 200, { entries });
        return;
      }
    }

    // ── Protected endpoints: require valid BPC ───────────────────────────────
    if (path.startsWith('/api/')) {
      const rawBody = await readBody(req);
      const digest = await crypto.subtle.digest('SHA-256', rawBody);
      const bodyHashValue = 'sha256:' + Buffer.from(digest).toString('base64url');

      const reqData: BPCRequestData = {
        pairId:     (req.headers['x-bpc-pair-id'] as string) ?? null,
        signedData: (req.headers['x-bpc-signed-data'] as string) ?? null,
        signature:  (req.headers['x-bpc-signature'] as string) ?? null,
        version:    (req.headers['x-bpc-version'] as string) ?? null,
        bodyHash:   bodyHashValue,
        method,
        path,
        ip,
      };

      const result = await verifyBPCRequest(reqData, registry, nonceStore, anomaly, {
        sigWindowMs:   60_000,
        ipRateLimiter,                    // pre-auth IP flood protection
        rateLimiter:   pairRateLimiter,   // per-pair budget
        auditLog,
      });

      if (!result.ok) {
        const errCode = result.error ?? 'unknown_error';
        const httpStatus = BPC_ERRORS[errCode]?.httpStatus ?? 401;
        log(method, path, `DENIED (${errCode}) ${httpStatus}`);
        json(res, httpStatus, { error: errCode });
        return;
      }

      log(method, path, `PASS pair=${result.pairId}`);

      if (path === '/api/status') {
        json(res, 200, { status: 'ok', pair: result.pairId, scope: result.pair?.scope, timestamp: Date.now() });
        return;
      }

      if (path === '/api/users') {
        json(res, 200, { users: ['alice', 'bob', 'charlie'] });
        return;
      }

      // Admin-only endpoint: only 'admin' scoped pairs can DELETE
      if (path === '/api/admin' && method === 'DELETE') {
        if (result.pair?.scope !== 'admin') {
          log(method, path, `SCOPE VIOLATION pair=${result.pairId} scope=${result.pair?.scope}`);
          json(res, 403, { error: 'scope_violation' });
          return;
        }
        json(res, 200, { deleted: true, by: result.pairId });
        return;
      }

      json(res, 404, { error: 'not_found' });
      return;
    }

    // ── Fallback ─────────────────────────────────────────────────────────────
    json(res, 404, { error: 'not_found' });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    log(method, path, `ERROR: ${msg}`);
    json(res, 500, { error: 'internal_error' });
  }
});

// ── Global safety net (IL4-7: process must never crash silently) ──────────────
process.on('uncaughtException', (err) => {
  console.error('[CRITICAL] Uncaught exception — server continuing:', err);
});
process.on('unhandledRejection', (reason) => {
  console.error('[CRITICAL] Unhandled rejection — server continuing:', reason);
});

server.listen(PORT, () => {
  console.log(`BPC Full-Stack Example Server (IL4-7 Hardened) running on http://localhost:${PORT}`);
  console.log('Endpoints:');
  console.log('  POST /bpc/register                  -- Register a new pair');
  console.log('  POST /bpc/revoke                    -- Revoke a pair');
  console.log('  POST /bpc/rotate                    -- Pair rotation');
  console.log('  GET  /bpc/pairs    [admin auth req] -- List all pairs (redacted)');
  console.log('  GET  /bpc/anomaly  [admin auth req] -- Anomaly/threat stats');
  console.log('  GET  /bpc/audit/:pairId [admin req] -- Audit log for a pair');
  console.log('  GET  /api/status                    -- Protected: server status');
  console.log('  GET  /api/users                     -- Protected: user list');
  console.log('  DEL  /api/admin                     -- Protected: admin-only delete');
  console.log('');
  console.log('Admin auth: Authorization: Bearer <BPC_ADMIN_TOKEN>');
});
