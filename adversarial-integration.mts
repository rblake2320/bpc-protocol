import { spawn, type ChildProcess } from 'node:child_process';
import { once } from 'node:events';
import { createServer } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';

const adminToken = 'bpc-adversarial-admin-token-2026';
const port = await reserveLoopbackPort();
const serverUrl = `http://127.0.0.1:${port}`;
const environment = {
  ...process.env,
  BPC_ADMIN_TOKEN: adminToken,
  BPC_HOST: '127.0.0.1',
  BPC_PORT: String(port),
  BPC_TEST_ADMIN_TOKEN: adminToken,
  BPC_TEST_SERVER_URL: serverUrl,
};

const server = spawn(process.execPath, ['--import', 'tsx', 'demo/server.ts'], {
  env: environment,
  stdio: ['ignore', 'pipe', 'pipe'],
});
server.stdout?.pipe(process.stdout);
server.stderr?.pipe(process.stderr);

try {
  await waitForServer(server, serverUrl);
  await runSuite('adversarial-proof.mts');
  await runSuite('scope-escalation-suite.mts');
  console.log('Adversarial integration: PASS (HTTP attacks and scope escalation)');
} finally {
  await stop(server);
}

async function reserveLoopbackPort(): Promise<number> {
  const reservation = createServer();
  reservation.listen(0, '127.0.0.1');
  await once(reservation, 'listening');
  const address = reservation.address();
  if (!address || typeof address === 'string') throw new Error('Could not reserve a loopback port');
  const reservedPort = address.port;
  reservation.close();
  await once(reservation, 'close');
  return reservedPort;
}

async function waitForServer(serverProcess: ChildProcess, url: string): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (serverProcess.exitCode !== null) {
      throw new Error(`Adversarial server exited before readiness: ${serverProcess.exitCode}`);
    }
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch {
      // Startup races are expected until the listener is ready.
    }
    await delay(50);
  }
  throw new Error(`Adversarial server did not become ready at ${url}`);
}

async function runSuite(script: string): Promise<void> {
  const child = spawn(process.execPath, ['--import', 'tsx', script], {
    env: environment,
    stdio: 'inherit',
  });
  const [code, signal] = await once(child, 'exit') as [number | null, NodeJS.Signals | null];
  if (code !== 0) {
    throw new Error(`${script} failed: exit=${code} signal=${signal ?? 'none'}`);
  }
}

async function stop(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill('SIGTERM');
  await Promise.race([once(child, 'exit'), delay(2_000)]);
  if (child.exitCode === null && child.signalCode === null) {
    child.kill('SIGKILL');
    await once(child, 'exit');
  }
}
