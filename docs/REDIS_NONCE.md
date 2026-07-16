# Governed Redis Replay Backend

Every TypeScript BPC verifier that can accept the same pair must share one
atomic Redis namespace and the same canonical retention/quarantine
configuration. A process-local cache cannot reject a replay accepted by
another process and loses its history on restart.

## Production Composition

Production deployments use the asynchronous governed factory. It checks the
live Redis eviction policy, reconciles shared continuity state, and starts a
serialized fail-closed reconcile loop before it returns.

```ts
import Redis from 'ioredis';
import {
  createBPCServer,
  createGovernedRedisBackedNonceStore,
  verifyBPCRequest,
} from '@bpc/server';

const redis = new Redis(process.env.REDIS_URL!, {
  enableOfflineQueue: false,
  maxRetriesPerRequest: 1,
  connectTimeout: 2_000,
});

const expectedEpoch = process.env.BPC_EXPECTED_REDIS_EPOCH;
const replay = await createGovernedRedisBackedNonceStore(redis, {
  namespace: 'tax-prod-us1',
  sigWindowMs: 60_000,
  commandTimeoutMs: 2_000,
  reconcileIntervalMs: 5_000,
  // Supply only from a separately trusted checkpoint when one exists.
  ...(expectedEpoch ? { expectedEpoch } : {}),
});

const bpc = createBPCServer({ nonceStore: replay.nonceStore });

const result = await verifyBPCRequest(
  requestData,
  bpc.registry,
  bpc.nonceStore,
  bpc.anomaly,
  { ...replay.verifierConfig, auditLog: bpc.auditLog },
);

if (!result.ok) deny(result.error);

// Await this during graceful shutdown. It closes authorization first and
// drains the active reconcile wrapper. See the timeout boundary below.
await replay.stop();
```

The factory derives nonce retention as:

```text
2 * sigWindowMs + safetyBufferMs
```

The default 60-second signature window and 10-second safety buffer retain
nonces for 130 seconds. A fresh or missing continuity namespace enters a
shared quarantine for retention plus the continuity safety allowance (30
seconds by default). It opens only after that full horizon expires and a
successful reconciliation observes the same epoch.

The factory stores the derived retention and quarantine horizons in a shared
configuration key. A verifier with different values cannot join that namespace
or shorten the shared quarantine. All configuration, continuity, quarantine,
and nonce keys use the same Redis Cluster hash slot. The nonce Lua operation
validates the configuration, expected epoch, and shared quarantine and consumes
the nonce in one Redis EVAL. A state loss or epoch change observed after the
local middleware preflight therefore denies without writing the nonce.

## Failure Contract

The following conditions fail closed:

- startup `CONFIG GET maxmemory-policy` is unavailable, malformed, ambiguous,
  or not exactly `noeviction`;
- continuity bootstrap or periodic reconciliation times out or fails;
- the shared retention/quarantine configuration is absent, malformed, or
  different from the verifier's derived values;
- the continuity marker is absent, changes epoch, or has malformed quarantine
  state;
- Redis rejects, times out, disconnects, returns an unknown script response,
  becomes read-only, or reports OOM;
- the reconciler is stopped.

Continuity uncertainty returns `authorization_quarantined`; Redis command
uncertainty returns `replay_store_unavailable`. Both map to HTTP 503. There is
no automatic memory fallback.

The periodic loop serializes its `reconcile()` wrappers, contains observer
errors, and provides asynchronous idempotent stop. The configured interval must
be shorter than the complete nonce retention horizon.

JavaScript timeouts cannot cancel an ioredis command already sent to Redis. A
timed-out underlying CONFIG/EVAL may therefore settle after its wrapper returns,
and a later loop tick can overlap that external operation. `stop()` closes the
local authorization gate and drains the active wrapper, but it does not promise
to cancel or await an already-timed-out Redis command. This remains fail closed:
the timed-out request is denied, a late nonce write cannot retroactively
authorize it, shared continuity scripts only establish or extend safety state,
and the stopped local gate cannot reopen. A named regression covers late nonce
consumption. Deployments that require command cancellation must close/dispose
their Redis connection after stopping the verifier.

## Redis Deployment Requirements

- authenticated, encrypted, network-restricted access;
- `maxmemory-policy noeviction`;
- Redis ACLs that prevent the verifier identity from changing policy and limit
  administrative mutation to separately governed operators;
- bounded connection and command deadlines;
- monitoring for rejected commands, evictions, policy changes, persistence,
  replication state, restarts, and failover;
- one environment-specific namespace per authorization boundary;
- identical signature-window, safety-buffer, and continuity-allowance settings
  for every verifier in that namespace (enforced by the shared config key);
- an external continuity checkpoint when rollback detection is required.

In Redis Cluster, configure and verify `noeviction` on every node. The factory's
single client `CONFIG GET` is not evidence that every cluster member has the
same policy, even though the hash tag keeps the governed keys in one slot.

## Bounded Claim And Residual Risk

The implemented scripts establish atomic first-use ordering and fail-closed
continuity checks on the Redis instance that executes them. They detect an
absent continuity marker, a changed epoch relative to a running verifier or
supplied trusted `expectedEpoch`, a horizon mismatch, and shared quarantine.

They do **not** prove:

- that asynchronous replication acknowledged the latest nonce before failover;
- that a restored snapshot with the same internally consistent epoch is newer
  than a prior accepted request;
- that a cold process without a trusted `expectedEpoch` can distinguish any
  existing restored epoch, including a different historical epoch, from the
  intended live deployment;
- that an administrator did not selectively delete a nonce while retaining the
  epoch;
- that `maxmemory-policy` cannot change between periodic policy checks;
- that every Redis Cluster member shares the policy observed by one client;
- that Redis persistence, storage, or backups are lossless.

Close those boundaries with deployment-specific durability, ACLs, external
checkpoints/anchors, and measured restart/failover evidence. See `PARKED.md`.

## Development-Only Helper

`createRedisBackedNonceStore()` remains available only for isolated tests and
development and now requires:

```ts
continuityMode: 'ungoverned-development'
```

It performs atomic `SET NX PX` but has no epoch or quarantine. It must not be
used as evidence for governed restart or failover behavior. Direct
`RedisNonceStore` and `ServerNonceStore` callers also own every composition
invariant themselves.

## Executable Evidence

Run the non-mocked integration against actual Redis:

```powershell
$env:BPC_TEST_REDIS_URL = "redis://127.0.0.1:6379"
npm run build
npm run test:redis
```

The integration imports built package entry points and exercises two verifier
clients, 64 concurrent uses of one signed request, TTL derivation, namespace
isolation, shared fresh-state quarantine, horizon-based recovery, an epoch
swap and scoped state loss injected after local preflight, heterogeneous-horizon
rejection, disconnect, a live unsafe-policy rejection, and real `noeviction`
OOM behavior. Python multi-node replay storage remains a separate parked
capability.
