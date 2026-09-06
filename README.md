# BPC -- Bound Pair Credentials

BPC is a pair-authorized, per-request authentication protocol. It combines an
ECDSA P-256 signature, an HKDF-SHA-256-derived HMAC verifier, request binding,
freshness checks, and server-side pair lifecycle state.

## What It Addresses

Static bearer keys can be copied and replayed without proving possession of a
second credential. BPC requires a request to satisfy all configured checks:

| Layer | Verified condition |
|---|---|
| Pair signing key | The canonical request signature verifies against the registered public key. |
| Closed pair registry | The pair exists, is active, and has an allowed coarse scope. |
| Secret-derived HMAC | The request contains the expected HMAC over its nonce and timestamp. |
| Freshness | The signed timestamp is within the configured window and the nonce is consumed once. |
| Request binding | Method, path, body hash, pair ID, and protocol version match the signed payload. |
| Rule-based anomaly tracking | Configured failures and request patterns are recorded for policy response. |

WebCrypto clients can generate an ECDSA key with `extractable: false`. That
prevents ordinary JavaScript key export; it does not establish hardware or
physical-device identity. Hardware binding requires a separately implemented
and assessed attestation mechanism.

## Packages

- `@bpc/core`: canonicalization, ECDSA, HKDF/HMAC, secret-policy helpers
- `@bpc/server`: pair registry, verifier, nonce backends, anomaly tracking,
  audit backends, rotation, replication, and promotion controls
- `@bpc/client-sdk`: registration and signed-request client
- `bpc-client` and `bpc-server`: Python client and middleware packages

## Build And Test

```bash
npm ci
npm run build
npm test
npm run test:adversarial
npm run test:interop
npm run test:pack
```

Distributed replay testing uses built package entry points and a real Redis
service. It exercises two independent verifiers, a 64-request race, TTL,
namespace isolation, shared continuity quarantine and recovery, an epoch swap
between preflight and consumption, unsafe-policy rejection, disconnect, and
`noeviction` OOM denial:

```powershell
$env:BPC_TEST_REDIS_URL = "redis://127.0.0.1:6379"
npm run test:redis
```

Persistent-store testing uses a real PostgreSQL service:

```powershell
$env:BPC_TEST_POSTGRES_URL = "postgresql://bpc_test:password@127.0.0.1:5432/bpc_test"
npm run test:postgres
```

The durable-outbox PostgreSQL mechanism has a separate mandatory integration:

```powershell
$env:BPC_TEST_POSTGRES_URL = "postgresql://bpc_test:password@127.0.0.1:5432/bpc_test"
npm run test:postgres:ha
```

See [docs/REDIS_NONCE.md](docs/REDIS_NONCE.md) for production wiring and
[docs/SCOPE_MODEL.md](docs/SCOPE_MODEL.md) for the deliberately closed scope
model. See [docs/POSTGRES_TRANSACTOR.md](docs/POSTGRES_TRANSACTOR.md) for
transaction outcome, deadline, connection-disposal, and deployment boundaries,
and [docs/DURABLE_PAIR_AUTHORITY.md](docs/DURABLE_PAIR_AUTHORITY.md) for the
encrypted transactional pair-store and v2-to-v3 migration boundary.

`test:adversarial` starts an isolated loopback demo server on an ephemeral port
and runs the HTTP attack and scope-escalation suites. `test:interop` executes
Python and TypeScript against each other's signature,
HKDF/HMAC, and fingerprint formats. `test:pack` builds each npm workspace and
verifies the publish manifest includes compiled `dist` entry points.

`test:postgres` requires `BPC_TEST_POSTGRES_URL` and exercises the real
PostgreSQL pair store, including authorization-affecting security fields and a
full connection restart. It is not replaced by an in-memory store in CI.

## Security Boundaries

Narrowly established properties include:

- Retained nonce state rejects a second use of the same nonce.
- The default verifier rejects timestamps outside a plus/minus 60-second window.
- Method, path, body hash, pair ID, and version are covered by the canonical
  signed request.
- Unknown, inactive, expired, capped, or revoked pairs fail authorization.
- Rotation is authorized by the existing pair key and preserves the prior
  scope rather than permitting scope escalation.
- The governed TypeScript Redis factory derives nonce retention from the
  signature window, requires an explicit namespace and live `noeviction`,
  binds one shared retention/quarantine configuration, reconciles a shared
  continuity quarantine, and validates the config and expected epoch in the
  same Redis EVAL that consumes the nonce. Unknown state is a named fail-closed
  denial. Uncheckpointed cold-start rollback (including a different historical
  epoch), same-epoch rollback, asynchronous replication loss, selective
  deletion, and runtime policy drift remain deployment boundaries; the old
  non-continuity Redis helper requires an explicit development marker.
- Redis and PostgreSQL backends are implemented for shared and persistent
  state. Production claims still require deployment-specific failure,
  recovery, durability, and access-control evidence.

BPC does not independently provide:

- transport confidentiality;
- hardware attestation or proof of physical-device identity;
- protection after compromise of every credential factor or the verifier host;
- application-level resource authorization;
- FIPS 140 validation, DoD Impact Level authorization, an ATO, or regulatory
  compliance;
- post-quantum security.

Algorithms named in this repository are not a claim that the deployed runtime
uses a CMVP-validated module. That determination depends on the exact module,
version, operating mode, and environment.

## Status

Current TypeScript workspace version: `0.2.0` (beta reference
implementation). Python package versions remain independently versioned.
Interfaces can change until a release is explicitly tagged and published.

Security findings and corrections are documented in [SECURITY.md](SECURITY.md).
Removed or rejected claims are retained in [PARKED.md](PARKED.md), with design
rationale in [WHY.md](WHY.md).

## Attribution

Conceived and designed by R. Blake.
