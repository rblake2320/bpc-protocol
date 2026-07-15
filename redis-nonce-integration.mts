import { randomUUID } from 'node:crypto';

import Redis from 'ioredis';

import { RedisNonceStore, ServerNonceStore } from './packages/server/src/index.js';

const url = process.env.BPC_TEST_REDIS_URL;
if (!url) {
  throw new Error('BPC_TEST_REDIS_URL is required; this test never substitutes an in-memory backend');
}

const redisOptions = {
  connectTimeout: 5_000,
  lazyConnect: true,
  maxRetriesPerRequest: 1,
} as const;
const redis = new Redis(url, redisOptions);
const redisPeer = new Redis(url, redisOptions);
const prefix = `bpc:test:${randomUUID()}:`;

try {
  await redis.connect();
  await redisPeer.connect();
  const store = new ServerNonceStore(new RedisNonceStore(redis, prefix), 2_000);
  const peerStore = new ServerNonceStore(new RedisNonceStore(redisPeer, prefix), 2_000);
  const nonce = randomUUID();

  const first = await store.checkAndConsume(nonce);
  const replay = await store.checkAndConsume(nonce);
  const ttl = await redis.pttl(prefix + nonce);

  if (first !== false) throw new Error('first nonce use was incorrectly classified as replay');
  if (replay !== true) throw new Error('second nonce use was not rejected as replay');
  if (ttl <= 0 || ttl > 2_000) throw new Error(`nonce TTL outside expected range: ${ttl}`);

  const racedNonce = randomUUID();
  const outcomes = await Promise.all(
    Array.from({ length: 64 }, (_, index) =>
      (index % 2 === 0 ? store : peerStore).checkAndConsume(racedNonce)),
  );
  const firstUseWinners = outcomes.filter((isReplay) => !isReplay).length;
  const replayRejections = outcomes.filter(Boolean).length;
  if (firstUseWinners !== 1 || replayRejections !== 63) {
    throw new Error(
      `distributed nonce race was not atomic: winners=${firstUseWinners}, replays=${replayRejections}`,
    );
  }

  console.log('Redis nonce integration: PASS (two-client atomic race, replay rejection, TTL)');
} finally {
  const keys = await redis.keys(prefix + '*').catch(() => [] as string[]);
  if (keys.length > 0) await redis.del(...keys);
  redis.disconnect();
  redisPeer.disconnect();
}
