import { randomUUID } from 'node:crypto';

import Redis from 'ioredis';

import { BPCClient } from './packages/client-sdk/dist/index.js';
import { generateKeypair, hashSecret } from './packages/core/dist/index.js';
import {
  AnomalyEngine,
  BPC_ERRORS,
  MemoryAnomalyStore,
  MemoryPairStore,
  PairRegistry,
  createRedisBackedNonceStore,
  verifyBPCRequest,
} from './packages/server/dist/index.js';
import type { BPCRequestData } from './packages/server/dist/index.js';

const url = process.env.BPC_TEST_REDIS_URL;
if (!url) {
  throw new Error('BPC_TEST_REDIS_URL is required; this test never substitutes an in-memory backend');
}

const redisOptions = {
  connectTimeout: 5_000,
  enableOfflineQueue: false,
  lazyConnect: true,
  maxRetriesPerRequest: 1,
  retryStrategy: () => null,
} as const;
const redis = new Redis(url, redisOptions);
const redisPeer = new Redis(url, redisOptions);
const runNamespace = `it-${randomUUID()}`;
const sigWindowMs = 60_000;
let passed = 0;

function assert(condition: unknown, name: string): asserts condition {
  if (!condition) throw new Error(name);
  passed++;
  console.log(`  PASS ${name}`);
}

function requestFromHeaders(headers: Awaited<ReturnType<BPCClient['signRequest']>>): BPCRequestData {
  return {
    pairId: headers['X-BPC-Pair-ID'],
    signedData: headers['X-BPC-Signed-Data'],
    signature: headers['X-BPC-Signature'],
    version: headers['X-BPC-Version'],
    bodyHash: 'sha256:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU',
    method: 'GET',
    path: '/api/data',
    ip: '127.0.0.1',
  };
}

function memoryAnomaly(): AnomalyEngine {
  return new AnomalyEngine(new MemoryAnomalyStore());
}

try {
  await redis.connect();
  await redisPeer.connect();

  const pairStore = new MemoryPairStore();
  const registryA = new PairRegistry(pairStore);
  const registryB = new PairRegistry(pairStore);
  const keypair = await generateKeypair();
  const secret = 'redis-integration-secret-2026';
  const pairId = await registryA.registerDirect({
    name: 'redis-two-verifier-test',
    scope: 'read',
    mode: 'development',
    secretHash: await hashSecret(secret),
    pubJwk: keypair.pubJwk,
  });
  const client = new BPCClient({
    serverUrl: 'http://127.0.0.1',
    pairId,
    keypair,
    secret,
  });

  const configuredA = createRedisBackedNonceStore(redis, { namespace: runNamespace, sigWindowMs });
  const configuredB = createRedisBackedNonceStore(redisPeer, { namespace: runNamespace, sigWindowMs });
  assert(configuredA.retentionMs === 130_000, 'standalone builder derives the 130s retention invariant');
  assert(configuredA.keyPrefix === configuredB.keyPrefix, 'independent verifiers share the explicit deployment namespace');

  const signed = await client.signRequest('GET', '/api/data');
  const request = requestFromHeaders(signed);
  const outcomes = await Promise.all(
    Array.from({ length: 64 }, (_, index) => verifyBPCRequest(
      request,
      index % 2 === 0 ? registryA : registryB,
      index % 2 === 0 ? configuredA.nonceStore : configuredB.nonceStore,
      memoryAnomaly(),
      { sigWindowMs, enableTarpit: false },
    )),
  );
  const accepted = outcomes.filter((result) => result.ok).length;
  const replayed = outcomes.filter((result) => result.error === 'replay_detected').length;
  assert(accepted === 1 && replayed === 63, 'two real verifiers authorize one first use and deny 63 concurrent replays');

  const payload = JSON.parse(Buffer.from(signed['X-BPC-Signed-Data'], 'base64url').toString()) as { nonce: string };
  const ttl = await redis.pttl(configuredA.keyPrefix + payload.nonce);
  assert(ttl > 120_000 && ttl <= configuredA.retentionMs, 'accepted nonce retains the derived Redis TTL');

  const isolated = createRedisBackedNonceStore(redis, {
    namespace: `${runNamespace}-isolated`,
    sigWindowMs,
  });
  const isolatedResult = await verifyBPCRequest(
    request,
    registryA,
    isolated.nonceStore,
    memoryAnomaly(),
    { sigWindowMs, enableTarpit: false },
  );
  assert(isolatedResult.ok, 'an explicit second namespace is isolated from the first deployment');

  const disconnected = new Redis(url, redisOptions);
  await disconnected.connect();
  disconnected.disconnect();
  const unavailable = createRedisBackedNonceStore(disconnected, {
    namespace: `${runNamespace}-down`,
    sigWindowMs,
    commandTimeoutMs: 250,
  });
  const unavailableRequest = requestFromHeaders(await client.signRequest('GET', '/api/data'));
  const unavailableResult = await verifyBPCRequest(
    unavailableRequest,
    registryA,
    unavailable.nonceStore,
    memoryAnomaly(),
    { sigWindowMs, enableTarpit: false },
  );
  assert(
    !unavailableResult.ok && unavailableResult.error === 'replay_store_unavailable',
    'a disconnected real Redis client produces a named fail-closed denial',
  );
  assert(BPC_ERRORS['replay_store_unavailable']?.httpStatus === 503, 'standalone adapters map replay-store outage to HTTP 503');

  const oldMaxmemory = (await redis.config('GET', 'maxmemory'))[1] ?? '0';
  const oldPolicy = (await redis.config('GET', 'maxmemory-policy'))[1] ?? 'noeviction';
  try {
    const memoryInfo = await redis.info('memory');
    const usedMatch = /^used_memory:(\d+)$/m.exec(memoryInfo);
    if (!usedMatch) throw new Error('Redis INFO did not expose used_memory');
    await redis.config('SET', 'maxmemory-policy', 'noeviction');
    await redis.config('SET', 'maxmemory', String(Math.max(1, Number(usedMatch[1]) - 1)));

    const oomStore = createRedisBackedNonceStore(redis, {
      namespace: `${runNamespace}-oom`,
      sigWindowMs,
    });
    const oomRequest = requestFromHeaders(await client.signRequest('GET', '/api/data'));
    const oomResult = await verifyBPCRequest(
      oomRequest,
      registryA,
      oomStore.nonceStore,
      memoryAnomaly(),
      { sigWindowMs, enableTarpit: false },
    );
    assert(
      !oomResult.ok && oomResult.error === 'replay_store_unavailable',
      'real Redis noeviction/OOM refuses authorization instead of dropping nonce history',
    );
  } finally {
    await redis.config('SET', 'maxmemory', oldMaxmemory);
    await redis.config('SET', 'maxmemory-policy', oldPolicy);
  }

  console.log(`Redis standalone verifier integration: ${passed}/${passed} passed`);
} finally {
  const keys = await redis.keys(`bpc:${runNamespace}*`).catch(() => [] as string[]);
  if (keys.length > 0) await redis.del(...keys);
  redis.disconnect();
  redisPeer.disconnect();
}
