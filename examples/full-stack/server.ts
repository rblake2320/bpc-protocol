import { createServer, IncomingMessage, ServerResponse } from 'node:http';
import { createBPCServer, verifyBPCRequest, BPC_ERRORS, handleRotation } from '../../packages/server/src/index.ts';
import type { BPCRequestData, PairRegistration, RotationRequest } from '../../packages/server/src/index.ts';

const PORT = 3100;

const { registry, nonceStore, anomaly, store } = createBPCServer();

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
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

// Raise maxHeaderSize to 8 MB so oversized headers reach our middleware,
// which then rejects them with a proper JSON 400 (not a silent Node 431).
const server = createServer({ maxHeaderSize: 8 * 1024 * 1024 }, async (req: IncomingMessage, res: ServerResponse) => {
  const method = (req.method ?? 'GET').toUpperCase();
  const path = req.url ?? '/';

  try {
    // --- Registration endpoint (no BPC required) ---
    if (method === 'POST' && path === '/bpc/register') {
      const body = await readBody(req);
      const registration: PairRegistration = JSON.parse(body);

      // Dev mode: auto-approve
      const pairId = await registry.registerDirect(registration);
      log(method, path, `REGISTERED pair=${pairId}`);
      json(res, 200, { pairId, status: 'approved' });
      return;
    }

    // --- Revocation endpoint ---
    if (method === 'POST' && path === '/bpc/revoke') {
      const body = await readBody(req);
      const { pairId: targetPairId } = JSON.parse(body) as { pairId: string };
      if (!targetPairId) { json(res, 400, { error: 'missing_pair_id' }); return; }
      await registry.revoke(targetPairId);
      log(method, path, `REVOKED pair=${targetPairId}`);
      json(res, 200, { revoked: true, pairId: targetPairId });
      return;
    }

    // --- Rotation endpoint ---
    if (method === 'POST' && path === '/bpc/rotate') {
      const body = await readBody(req);
      const rotReq = JSON.parse(body) as RotationRequest;
      const result = await handleRotation(rotReq, store);
      if (!result.ok) {
        log(method, path, `ROTATION DENIED (${result.error})`);
        json(res, 401, { error: result.error });
        return;
      }
      log(method, path, `ROTATED old=${rotReq.oldPairId} new=${result.newPairId}`);
      json(res, 200, { newPairId: result.newPairId });
      return;
    }

    // --- Protected endpoints: require valid BPC ---
    if (path.startsWith('/api/')) {
      const reqData: BPCRequestData = {
        pairId: (req.headers['x-bpc-pair-id'] as string) ?? null,
        signedData: (req.headers['x-bpc-signed-data'] as string) ?? null,
        signature: (req.headers['x-bpc-signature'] as string) ?? null,
        version: (req.headers['x-bpc-version'] as string) ?? null,
        bodyHash: null,   // body hash enforcement optional for this example
        method,
        path,
        ip: req.socket.remoteAddress,
      };

      const result = await verifyBPCRequest(reqData, registry, nonceStore, anomaly);

      if (!result.ok) {
        const errCode = result.error ?? 'unknown_error';
        const httpStatus = BPC_ERRORS[errCode]?.httpStatus ?? 401;
        log(method, path, `DENIED (${errCode}) ${httpStatus}`);
        json(res, httpStatus, { error: errCode });
        return;
      }

      log(method, path, `PASS pair=${result.pairId}`);

      // Route to handlers
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

    // --- Fallback ---
    json(res, 404, { error: 'not_found' });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    log(method, path, `ERROR: ${msg}`);
    json(res, 500, { error: 'internal_error' });
  }
});

server.listen(PORT, () => {
  console.log(`BPC Full-Stack Example Server running on http://localhost:${PORT}`);
  console.log('Endpoints:');
  console.log('  POST /bpc/register    -- Register a new pair (dev mode: auto-approve)');
  console.log('  POST /bpc/revoke      -- Revoke a pair');
  console.log('  POST /bpc/rotate      -- Pair rotation (old key signs new pubJwk)');
  console.log('  GET  /api/status      -- Protected: returns server status + scope');
  console.log('  GET  /api/users       -- Protected: returns user list');
  console.log('  DEL  /api/admin       -- Protected: admin-only delete');
  console.log('');
});
