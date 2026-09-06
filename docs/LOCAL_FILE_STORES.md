# Local file stores

`@bpc/server` exports `FilePairStore`, `FileNonceBackend`, and `FileAnomalyStore`.
They implement the store interfaces for a single host. The default
`createBPCServer()` factory still uses memory stores; importing these classes
does not change a running server's persistence configuration.

```js
import { FileNonceBackend } from '@bpc/server';

const backend = new FileNonceBackend('/absolute/private/state/nonces.json');
const replay = await backend.checkAndConsume('request-nonce', 60_000);
// false: nonce consumed; true: already consumed and still unexpired.
```

Each operation acquires an exclusive adjacent `.lock`, loads current authority,
and validates it before use. Writes use an exclusive temporary file, file fsync,
and rename. Keep the state directory private to the service account. Missing
files initialize empty authority; malformed existing files are rejected.
The constructor alone does not validate existing file contents: execute the
required store operation during readiness checks and handle its rejection.

Lock contention returns `BPC_FILE_STORE_LOCK_UNAVAILABLE`; it is not a successful
operation. Locks are never automatically stolen. If a process dies holding a
lock, establish that its owner is gone and reconcile the persisted outcome
before operator recovery. Do not blindly delete locks or replay an action after
an unknown result. Lock-release failure can occur after a write was published.

| Claim | Implementation | Executable check |
|---|---|---|
| Published package exposes the stores | `packages/server/src/index.ts` | `npm run test:installed-file-store` imports installed tarballs |
| New instances preserve nonce replay and anomaly counts | `packages/server/src/file-store.ts` | Installed consumer gate |
| Malformed authority is rejected | File-store decoders | Installed consumer and `file-store-atomic.test.ts` |
| Local process contention does not accept the same nonce twice in the tested race | Exclusive lock plus fresh read | `file-store-atomic.test.ts` launches separate Node processes |

Build before running installed acceptance:

```sh
npm ci
npm run build
npm run test:installed-file-store
```

The gate retains tarball hashes, child command transcripts and its result in a
new temporary evidence directory printed on completion. It installs into a
separate consumer rather than importing workspace source.

These checks do not prove arbitrary crash-point recovery, power-loss survival,
directory-fsync durability, automatic stale-lock recovery, or distributed
authority. Single-host file-store evidence does not transfer to Redis,
PostgreSQL, or an HA deployment, which have separate controls and acceptance.
