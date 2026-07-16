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
  createGovernedRedisBackedNonceStore,
  verifyBPCRequest,
} from './packages/server/dist/index.js';
import type {
  BPCRequestData,
  GovernedRedisBackedNonceStore,
  RedisAtomicClient,
} from './packages/server/dist/index.js';

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
const retentionMs = 130_000;
const quarantineMs = 160_000;
let passed = 0;
const stores: GovernedRedisBackedNonceStore[] = [];

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

function continuityKey(namespace: string): string {
  return `bpc:{${namespace}}:continuity:v2`;
}

function quarantineKey(namespace: string): string {
  return `bpc:{${namespace}}:continuity-quarantine:v2`;
}

function continuityConfigKey(namespace: string): string {
  return `bpc:{${namespace}}:continuity-config:v2`;
}

async function establishContinuity(namespace: string, epoch: string): Promise<void> {
  await redis.del(
    continuityKey(namespace),
    quarantineKey(namespace),
    continuityConfigKey(namespace),
  );
  await redis.set(continuityKey(namespace), epoch);
  await redis.set(continuityConfigKey(namespace), `${retentionMs}:${quarantineMs}`);
}

async function governed(
  client: RedisAtomicClient,
  namespace: string,
): Promise<GovernedRedisBackedNonceStore> {
  const configured = await createGovernedRedisBackedNonceStore(client, {
    namespace,
    sigWindowMs,
    reconcileIntervalMs: 5_000,
  });
  stores.push(configured);
  return configured;
}

function interceptConsume(
  client: Redis,
  readHook: () => (() => Promise<void>) | undefined,
): RedisAtomicClient {
  return {
    config: (op, parameter) => client.config(op, parameter),
    eval: async (script, numKeys, ...args) => {
      if (Number(numKeys) === 4) {
        const hook = readHook();
        if (hook) await hook();
      }
      return client.eval(script, numKeys, ...args);
    },
  };
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

  await establishContinuity(runNamespace, 'epoch-live-established');
  const configuredA = await governed(redis, runNamespace);
  const configuredB = await governed(redisPeer, runNamespace);
  assert(configuredA.retentionMs === 130_000, 'governed builder derives the 130s retention invariant');
  assert(configuredA.keyPrefix === configuredB.keyPrefix, 'independent verifiers share the explicit deployment namespace');
  assert(configuredA.continuityKey === configuredB.continuityKey, 'independent verifiers share one continuity epoch');

  const signed = await client.signRequest('GET', '/api/data');
  const request = requestFromHeaders(signed);
  const outcomes = await Promise.all(
    Array.from({ length: 64 }, (_, index) => verifyBPCRequest(
      request,
      index % 2 === 0 ? registryA : registryB,
      index % 2 === 0 ? configuredA.nonceStore : configuredB.nonceStore,
      memoryAnomaly(),
      {
        ...(index % 2 === 0 ? configuredA.verifierConfig : configuredB.verifierConfig),
        enableTarpit: false,
      },
    )),
  );
  const accepted = outcomes.filter((result) => result.ok).length;
  const replayed = outcomes.filter((result) => result.error === 'replay_detected').length;
  assert(accepted === 1 && replayed === 63, 'two real verifiers authorize one first use and deny 63 concurrent replays');

  const payload = JSON.parse(Buffer.from(signed['X-BPC-Signed-Data'], 'base64url').toString()) as { nonce: string };
  const ttl = await redis.pttl(configuredA.keyPrefix + payload.nonce);
  assert(ttl > 120_000 && ttl <= configuredA.retentionMs, 'accepted nonce retains the derived Redis TTL');

  const isolatedNamespace = `${runNamespace}-isolated`;
  await establishContinuity(isolatedNamespace, 'epoch-isolated-established');
  const isolated = await governed(redis, isolatedNamespace);
  const isolatedResult = await verifyBPCRequest(
    request,
    registryA,
    isolated.nonceStore,
    memoryAnomaly(),
    { ...isolated.verifierConfig, enableTarpit: false },
  );
  assert(isolatedResult.ok, 'an explicit second namespace is isolated from the first deployment');

  const freshNamespace = `${runNamespace}-fresh`;
  const freshA = await governed(redis, freshNamespace);
  const freshB = await governed(redisPeer, freshNamespace);
  const freshHeaders = await client.signRequest('GET', '/api/data');
  const freshRequest = requestFromHeaders(freshHeaders);
  const freshPayload = JSON.parse(
    Buffer.from(freshHeaders['X-BPC-Signed-Data'], 'base64url').toString(),
  ) as { nonce: string };
  const [freshResultA, freshResultB] = await Promise.all([
    verifyBPCRequest(
      freshRequest,
      registryA,
      freshA.nonceStore,
      memoryAnomaly(),
      { ...freshA.verifierConfig, enableTarpit: false },
    ),
    verifyBPCRequest(
      freshRequest,
      registryB,
      freshB.nonceStore,
      memoryAnomaly(),
      { ...freshB.verifierConfig, enableTarpit: false },
    ),
  ]);
  assert(
    freshResultA.error === 'authorization_quarantined'
      && freshResultB.error === 'authorization_quarantined',
    'two verifiers on an empty namespace share a fail-closed quarantine',
  );
  const freshQuarantineTtl = await redis.pttl(freshA.quarantineKey);
  assert(
    freshQuarantineTtl >= freshA.retentionMs,
    'fresh-state quarantine persists for at least the complete nonce horizon',
  );
  assert(
    (await redis.exists(freshA.keyPrefix + freshPayload.nonce)) === 0,
    'shared quarantine denies before consuming the request nonce',
  );

  const swapNamespace = `${runNamespace}-swap`;
  await establishContinuity(swapNamespace, 'epoch-before-swap');
  let swapHook: (() => Promise<void>) | undefined;
  const swapStore = await governed(interceptConsume(redis, () => {
    const hook = swapHook;
    swapHook = undefined;
    return hook;
  }), swapNamespace);
  const swapHeaders = await client.signRequest('GET', '/api/data');
  const swapPayload = JSON.parse(
    Buffer.from(swapHeaders['X-BPC-Signed-Data'], 'base64url').toString(),
  ) as { nonce: string };
  swapHook = async () => {
    await redisPeer.set(swapStore.continuityKey, 'epoch-after-swap');
  };
  const swapResult = await verifyBPCRequest(
    requestFromHeaders(swapHeaders),
    registryA,
    swapStore.nonceStore,
    memoryAnomaly(),
    { ...swapStore.verifierConfig, enableTarpit: false },
  );
  assert(
    swapResult.error === 'authorization_quarantined',
    'atomic consume detects an epoch swap after local preflight',
  );
  assert(
    (await redis.exists(swapStore.keyPrefix + swapPayload.nonce)) === 0,
    'epoch-swap denial does not consume the request nonce',
  );

  const lossNamespace = `${runNamespace}-loss`;
  await establishContinuity(lossNamespace, 'epoch-before-loss');
  let lossHook: (() => Promise<void>) | undefined;
  const lossStore = await governed(interceptConsume(redis, () => {
    const hook = lossHook;
    lossHook = undefined;
    return hook;
  }), lossNamespace);
  const lossHeaders = await client.signRequest('GET', '/api/data');
  const lossPayload = JSON.parse(
    Buffer.from(lossHeaders['X-BPC-Signed-Data'], 'base64url').toString(),
  ) as { nonce: string };
  const firstLossResult = await verifyBPCRequest(
    requestFromHeaders(lossHeaders),
    registryA,
    lossStore.nonceStore,
    memoryAnomaly(),
    { ...lossStore.verifierConfig, enableTarpit: false },
  );
  assert(firstLossResult.ok, 'request is accepted before scoped Redis state loss');
  lossHook = async () => {
    await redis.del(
      lossStore.continuityKey,
      lossStore.quarantineKey,
      lossStore.continuityConfigKey,
      lossStore.keyPrefix + lossPayload.nonce,
    );
  };
  const postLossReplay = await verifyBPCRequest(
    requestFromHeaders(lossHeaders),
    registryA,
    lossStore.nonceStore,
    memoryAnomaly(),
    { ...lossStore.verifierConfig, enableTarpit: false },
  );
  assert(
    postLossReplay.error === 'authorization_quarantined',
    'scoped Redis state loss converts a formerly accepted replay into quarantine',
  );
  assert(
    (await redis.exists(lossStore.keyPrefix + lossPayload.nonce)) === 0,
    'state-loss quarantine is established without rewriting the lost nonce',
  );

  let heterogeneousRejected = false;
  try {
    await createGovernedRedisBackedNonceStore(redisPeer, {
      namespace: runNamespace,
      sigWindowMs: 30_000,
      reconcileIntervalMs: 5_000,
    });
  } catch (error) {
    heterogeneousRejected = (error as { code?: string }).code
      === 'redis_continuity_config_mismatch';
  }
  assert(
    heterogeneousRejected,
    'real Redis rejects a second verifier with a different namespace horizon',
  );
  assert(
    (await redis.pttl(configuredA.quarantineKey)) >= configuredA.retentionMs,
    'horizon mismatch preserves quarantine for at least the longer retention window',
  );

  const disconnected = new Redis(url, redisOptions);
  await disconnected.connect();
  const downNamespace = `${runNamespace}-down`;
  await establishContinuity(downNamespace, 'epoch-before-disconnect');
  const unavailable = await governed(disconnected, downNamespace);
  disconnected.disconnect();
  const unavailableRequest = requestFromHeaders(await client.signRequest('GET', '/api/data'));
  const unavailableResult = await verifyBPCRequest(
    unavailableRequest,
    registryA,
    unavailable.nonceStore,
    memoryAnomaly(),
    { ...unavailable.verifierConfig, enableTarpit: false },
  );
  assert(
    !unavailableResult.ok && unavailableResult.error === 'replay_store_unavailable',
    'a disconnected real Redis client produces a named fail-closed denial',
  );
  assert(BPC_ERRORS['replay_store_unavailable']?.httpStatus === 503, 'adapters map replay-store outage to HTTP 503');

  const recoveryNamespace = `${runNamespace}-recovery`;
  const recovery = await createGovernedRedisBackedNonceStore(redis, {
    namespace: recoveryNamespace,
    sigWindowMs: 25,
    safetyBufferMs: 0,
    continuitySafetyAllowanceMs: 0,
    reconcileIntervalMs: 10,
  });
  stores.push(recovery);
  let initiallyQuarantined = false;
  try {
    recovery.continuityGuard.assertAcceptable();
  } catch (error) {
    initiallyQuarantined = (error as { code?: string }).code === 'authorization_quarantined';
  }
  assert(initiallyQuarantined, 'fresh continuity starts closed before the complete replay horizon');
  await new Promise((resolve) => setTimeout(resolve, 100));
  recovery.continuityGuard.assertAcceptable();
  assert(
    !(await recovery.nonceStore.checkAndConsume('after-full-horizon')),
    'fresh continuity opens only after quarantine expiration and reconciliation',
  );

  const oldMaxmemory = (await redis.config('GET', 'maxmemory'))[1] ?? '0';
  const oldPolicy = (await redis.config('GET', 'maxmemory-policy'))[1] ?? 'noeviction';
  let unsafePolicyRejected = false;
  try {
    await redis.config('SET', 'maxmemory-policy', 'allkeys-lru');
    await createGovernedRedisBackedNonceStore(redis, {
      namespace: `${runNamespace}-unsafe-policy`,
      sigWindowMs,
    });
  } catch (error) {
    unsafePolicyRejected = (error as { code?: string }).code === 'redis_eviction_policy_unsafe';
  } finally {
    await redis.config('SET', 'maxmemory-policy', oldPolicy);
  }
  assert(unsafePolicyRejected, 'real Redis startup rejects an eviction-capable maxmemory policy');

  const oomNamespace = `${runNamespace}-oom`;
  await establishContinuity(oomNamespace, 'epoch-before-oom');
  const oomStore = await governed(redis, oomNamespace);
  try {
    const memoryInfo = await redis.info('memory');
    const usedMatch = /^used_memory:(\d+)$/m.exec(memoryInfo);
    if (!usedMatch) throw new Error('Redis INFO did not expose used_memory');
    await redis.config('SET', 'maxmemory-policy', 'noeviction');
    await redis.config('SET', 'maxmemory', String(Math.max(1, Number(usedMatch[1]) - 1)));

    const oomRequest = requestFromHeaders(await client.signRequest('GET', '/api/data'));
    const oomResult = await verifyBPCRequest(
      oomRequest,
      registryA,
      oomStore.nonceStore,
      memoryAnomaly(),
      { ...oomStore.verifierConfig, enableTarpit: false },
    );
    assert(
      !oomResult.ok && oomResult.error === 'replay_store_unavailable',
      'real Redis noeviction/OOM refuses authorization instead of dropping nonce history',
    );
  } finally {
    await redis.config('SET', 'maxmemory', oldMaxmemory);
    await redis.config('SET', 'maxmemory-policy', oldPolicy);
  }

  console.log(`Redis governed verifier integration: ${passed}/${passed} passed`);
} finally {
  await Promise.all(stores.map((store) => store.stop().catch(() => {})));
  const keys = await redis.keys(`bpc:{${runNamespace}*`).catch(() => [] as string[]);
  if (keys.length > 0) await redis.del(...keys);
  redis.disconnect();
  redisPeer.disconnect();
}
