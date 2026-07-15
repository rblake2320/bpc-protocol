# Standalone Redis Nonce Backend

Every TypeScript BPC verifier that can accept the same pair must share one
atomic nonce namespace. A process-local cache cannot reject a replay that was
accepted by another process and loses its history on restart.

## Safe Composition

Use the validated builder rather than choosing a Redis TTL independently from
the BPC signature window:

```ts
import Redis from 'ioredis';
import {
  createBPCServer,
  createRedisBackedNonceStore,
  verifyBPCRequest,
} from '@bpc/server';

const sigWindowMs = 60_000;
const redis = new Redis(process.env.REDIS_URL!, {
  enableOfflineQueue: false,
  maxRetriesPerRequest: 1,
  connectTimeout: 2_000,
});

const replay = createRedisBackedNonceStore(redis, {
  namespace: 'tax-prod-us1',
  sigWindowMs,
  commandTimeoutMs: 2_000,
});

const bpc = createBPCServer({ nonceStore: replay.nonceStore });

// In the protected-route adapter, construct BPCRequestData from the exact
// received method, path, headers, client IP, and SHA-256 hash of raw body bytes.
const result = await verifyBPCRequest(
  requestData,
  bpc.registry,
  bpc.nonceStore,
  bpc.anomaly,
  { sigWindowMs, auditLog: bpc.auditLog },
);

if (!result.ok) {
  // replay_store_unavailable maps to HTTP 503. Never fall back to memory.
  deny(result.error);
}
```

`createRedisBackedNonceStore()` requires an explicit deployment namespace and
derives retention as:

```text
2 * sigWindowMs + safetyBufferMs
```

The default 60-second signature window and 10-second safety buffer therefore
retain nonces for 130 seconds. Construction rejects invalid windows,
namespaces, and command deadlines before the server starts.

The low-level `RedisNonceStore` and `ServerNonceStore` exports remain available
for custom adapters. Callers using them directly own the TTL invariant and
must not cite the validated standalone-builder evidence.

## Failure Contract

The Redis command is atomic `SET key value NX PX ttl`. One verifier receives
`OK`; every concurrent verifier using the same namespace receives a null result
and treats the nonce as a replay.

Redis rejection, timeout, disconnect, read-only state, or OOM is uncertain
replay state. The verifier returns `replay_store_unavailable` and the HTTP
adapter should return 503. There is no automatic memory fallback.

Configure production Redis with:

- authenticated, encrypted, network-restricted access;
- `maxmemory-policy noeviction` so pressure rejects writes rather than deleting
  live replay evidence;
- bounded client connection and command deadlines;
- monitoring for rejected commands, evictions, replication state, persistence,
  restarts, and failover;
- an environment-specific namespace shared by exactly the verifiers in one
  authorization boundary.

## Restart And Data-Loss Boundary

Redis persistence and replication have deployment-specific loss windows. If an
operator cannot establish that every nonce accepted during the current request
acceptance horizon survived a restart or failover, BPC authorization must stay
quarantined for the full derived retention interval. AOF, RDB, or replication
configuration is not by itself proof that no latest nonce was lost.

The package does not automatically attest Redis durability or detect arbitrary
key deletion. That remains a deployment control and is parked as a stronger
continuity claim in `PARKED.md`.

## Executable Evidence

Run the non-mocked integration against an actual Redis service:

```powershell
$env:BPC_TEST_REDIS_URL = "redis://127.0.0.1:6379"
npm run build
npm run test:redis
```

The integration imports built package entry points, creates two independent BPC
verifiers, submits the same signed request 64 times concurrently, and requires
one authorization plus 63 replay denials. It also exercises TTL derivation,
namespace isolation, a disconnected client, and real Redis `noeviction` OOM
behavior. Python multi-node replay storage is a separate parked capability.
