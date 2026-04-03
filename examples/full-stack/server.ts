import { createServer, IncomingMessage, ServerResponse } from 'node:http';
import { PairRegistry, AnomalyEngine, ServerNonceStore, verifyBPCRequest } from '../../packages/server/src/index.ts';
import type { BPCRequestData, PairRegistration } from '../../packages/server/src/index.ts';

const PORT = 3100;

const registry = new PairRegistry();
const nonceStore = new ServerNonceStore();
const anomaly = new AnomalyEngine();

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

const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
  const method = (req.method ?? 'GET').toUpperCase();
  const path = req.url ?? '/';

  try {
    // --- Registration endpoint (no BPC required) ---
    if (method === 'POST' && path === '/bpc/register') {
      const body = await readBody(req);
      const registration: PairRegistration = JSON.parse(body);

      // Dev mode: auto-approve
      const pairId = registry.registerDirect(registration);
      log(method, path, `REGISTERED pair=${pairId}`);
      json(res, 200, { pairId, status: 'approved' });
      return;
    }

    // --- Protected endpoints: require valid BPC ---
    if (path.startsWith('/api/')) {
      const reqData: BPCRequestData = {
        pairId: (req.headers['x-bpc-pair-id'] as string) ?? null,
        signedData: (req.headers['x-bpc-signed-data'] as string) ?? null,
        signature: (req.headers['x-bpc-signature'] as string) ?? null,
        method,
        path,
      };

      const result = await verifyBPCRequest(reqData, registry, nonceStore, anomaly);

      if (!result.ok) {
        log(method, path, `DENIED (${result.error})`);
        json(res, 401, { error: result.error });
        return;
      }

      log(method, path, `PASS pair=${result.pairId}`);

      // Route to handlers
      if (path === '/api/status') {
        json(res, 200, { status: 'ok', pair: result.pairId, timestamp: Date.now() });
        return;
      }

      if (path === '/api/users') {
        json(res, 200, { users: ['alice', 'bob', 'charlie'] });
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
  console.log('  POST /bpc/register  — Register a new pair (dev mode: auto-approve)');
  console.log('  GET  /api/status    — Protected: returns server status');
  console.log('  GET  /api/users     — Protected: returns user list');
  console.log('');
});
