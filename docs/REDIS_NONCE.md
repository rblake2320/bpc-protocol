# Redis Nonce Backend

Distributed BPC verifiers must share nonce state. A process-local nonce cache
cannot detect a replay accepted by another process and loses its history on
restart.

```ts
import Redis from 'ioredis';
import { RedisNonceStore, ServerNonceStore } from '@bpc/server';

const redis = new Redis(process.env.REDIS_URL!);
const backend = new RedisNonceStore(redis, 'bpc:nonce:');
const nonceStore = new ServerNonceStore(backend, 130_000);
```

`RedisNonceStore` uses atomic `SET key value NX PX ttl`. The wrapper returns
`false` for a nonce's first use and `true` when that nonce already exists.

Run the non-mocked integration test against an actual Redis service:

```powershell
$env:BPC_TEST_REDIS_URL = "redis://127.0.0.1:6379"
npm run test:redis
```

The CI workflow starts Redis and runs this command. Production deployments must
also restrict Redis network access, authenticate the connection, use transport
protection where the deployment boundary requires it, and monitor persistence
and eviction policy. BPC's nonce TTL is intentionally finite; Redis is a replay
coordination service, not the audit system of record.
