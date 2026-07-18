# Design Decisions

## 2026-07-16: Measure quarantine horizons with a controlled clock

The fake Redis model represents a countdown, so reading its TTL after an async
boundary with the host clock can legitimately observe one millisecond less
than the value just written. A security regression should not widen its lower
bound to accommodate scheduling. The test freezes `Date.now()` around the
transition and therefore asserts the exact configured 1000ms horizon.

The root test entry point also runs core, server, and client workspaces through
a small sequential runner. It forwards caller arguments to every workspace and
stops immediately on the first nonzero result, improving failure locality and
preventing later workspace output from obscuring the first failure. Dedicated
runner tests bind both behaviors. This is an evidence control only; it neither
changes Redis time semantics nor expands the governed factory's deployment
claims.

## 2026-07-16: Make continuity and nonce consumption one governed operation

A local continuity preflight followed by an awaited nonce command has a
time-of-check/time-of-use gap: Redis can lose or swap state between the two.
Production composition now uses one Redis Lua operation to compare the
process's expected epoch, enforce one shared horizon configuration and
quarantine, and consume the nonce. All keys use one Redis Cluster hash slot so
the operation remains valid in a clustered deployment. A mismatched verifier
fails startup and extends, never shortens, the existing quarantine.

The factory is asynchronous because serving before live policy validation and
initial reconciliation is a fail-open startup race. An empty namespace is not
assumed trustworthy; it establishes quarantine before the epoch and waits the
complete replay horizon. Two independently starting verifiers therefore make
the same authorization decision.

The periodic reconciler wrapper is serialized and its stop operation is
awaitable. Shutdown closes the local gate before draining the active wrapper,
preventing its result from reopening authorization. JavaScript cannot cancel an
ioredis command that has already timed out; such a command can settle later and
mutate Redis safety state, but it cannot authorize the request already denied or
reopen the stopped local gate. Operational observers are not part of the
security decision and cannot crash the loop.

The low-level `SET NX PX` builder remains only with an explicit
`ungoverned-development` acknowledgement. Retaining it avoids unnecessary API
removal while preventing documentation or call sites from silently treating
atomic nonce insertion as restart/failover continuity.

This design deliberately does not call Redis replication strongly consistent.
Uncheckpointed cold restore, same-epoch rollback, asynchronous failover loss,
selective administrative deletion, and configuration drift between checks
require external checkpoints, deployment ACLs, durable topology evidence, and
recovery exercises.

## 2026-07-15: Return authorization evidence, not a live registry object

Consumers need the pair identity and coarse scope that the verifier actually
used. Returning a mutable `StoredPair` let concurrent lifecycle updates alter
those values after verification. The verifier now copies its authorization
context at the registry-read boundary, uses that copy throughout verification,
and returns a frozen snapshot. This bounds the established property to
in-flight evidence consistency; cancelling requests that already raced a later
revocation would require a store-level authorization version fence.

Health checks are transport/service operations, not authenticated principals.
They must be routed outside `verifyBPCRequest()` so they cannot yield `ok: true`
without a verified snapshot.

## 2026-07-15: Keep credential scopes closed

BPC authenticates a pair and enforces a small HTTP-method ceiling. It does not
attempt to replace application authorization. Wildcard scopes were rejected
because normalization, prefix ambiguity, and future namespace collisions can
widen privileges without changing a credential. See `docs/SCOPE_MODEL.md`.

## 2026-07-15: Require shared nonce state for distributed verification

Replay detection is a composition property. Every verifier that may accept the
same credential must use the same atomic nonce backend. The repository now has
a real Redis integration test and CI service rather than relying only on an
in-memory substitute.

## 2026-07-15: Bind replay retention to request acceptance

A caller-selected Redis TTL can be shorter than the period in which a signed
request remains acceptable, reopening replay after the key expires. The
standalone builder derives retention from both sides of the signature window
plus a safety allowance and rejects unsafe configuration before startup.

## 2026-07-15: Redis uncertainty is denial, never fallback

Timeout, disconnect, read-only state, OOM, and unknown Redis replies provide no
proof that a nonce was consumed. The verifier returns a named 503 denial and
does not fall back to local memory. Redis persistence and replication can still
have loss windows; after an uncertain failover, deployment policy must
quarantine authorization for the complete nonce-retention horizon.

## 2026-07-15: Separate algorithms from module validation

Documentation names the algorithms the code requests. It does not claim FIPS
validation unless the exact deployed cryptographic module, mode, version, and
environment have verified CMVP evidence.

## 2026-07-15: Use one cross-language wire format

Python cryptography emits ASN.1 DER ECDSA signatures while WebCrypto uses
64-byte IEEE P1363. The protocol now specifies P1363 and Python converts at its
boundary. Public-key fingerprints canonicalize only required JWK members so
runtime-added metadata cannot change principal identity.

## 2026-07-15: Hash exact transmitted body bytes

Request integrity depends on the bytes on the wire, not an equivalent parsed
object. The TypeScript client hashes exact strings, buffers, URL parameters, and
blobs, and rejects generated-boundary or streaming bodies without an explicit
adapter.

## 2026-07-15: Make HA ordering authenticated and explicit

Replica operations carry a signed source, sequence, timestamp, and operation.
Only an exact operation retry is idempotent. Stale, gapped, conflicting, or
expired operations fail closed. Durable sequence/apply state and distributed
fencing remain named deployment gates rather than implied capabilities.

## 2026-07-15: Treat lifecycle routes as administrative operations

Revocation mutates authorization state and therefore requires the admin
verifier. Browser demos call the real server route; they no longer change only
local UI state. Static admin and guard tokens require at least 32 bytes and use
constant-time comparison.

## 2026-07-15: Pin CI dependencies to immutable identities

CI is part of the release security boundary. GitHub Actions are pinned to full
commit identifiers and service images are pinned to content digests.
Readable version comments remain for maintenance, but upgrades require an
explicit review rather than following a mutable tag automatically.

The CI runtime targets Node 24 LTS. Node 20 reached end of life in 2026 and is
not an acceptable security-validation baseline. Node 26 remains the Current
line until its LTS transition, so it is not the release baseline yet.

## 2026-07-15: Test authorization state in the durable store

An in-memory pair-store test cannot prove that a production database preserves
authorization-affecting fields. The PostgreSQL integration therefore persists
and reloads usage caps, anomaly counters, ghost/canary identity, revocation,
and pending-registration timestamps through a complete connection restart.
Losing these fields can become fail-open behavior, so the test runs in CI
against a real digest-pinned PostgreSQL service.

## 2026-07-15: Make executable attack runners release gates

An attack script that is documented but not run by CI can silently drift until
it no longer reaches the control it claims to test. The HTTP adversarial and
scope-escalation runners now execute through one command that owns an isolated
loopback server. Static source observations and unavailable-endpoint skips are
not counted as passing attack evidence.

## 2026-07-18: Represent uncertain commit outcomes instead of guessing

Once a PostgreSQL client dispatches `COMMIT`, loss of the response proves neither
commit nor rollback. Treating that failure as a normal rollback could let a
caller retry and create a second authoritative mutation. The production
transactor returns `AmbiguousCommitError` with `committed="unknown"` unless
PostgreSQL explicitly reports `COMMIT` or `ROLLBACK`. Reconciliation uses the
durable idempotency key and checkpoint.

The adapter owns a total transaction deadline in addition to the server-side
statement timeout, verifies command tags, destroys failed connections, and keeps
serialization retries disabled unless explicitly enabled for replay-safe work.
The mandatory real-PostgreSQL harness now uses this same production adapter.

## 2026-07-18: Snapshot before awaiting injected collaborators

Cryptographic verification does not help if a caller, transport, database row,
or verifier can mutate the object being verified while an asynchronous operation
is pending. Durable-outbox inputs are now converted once to detached canonical
I-JSON, deep-frozen, and used exclusively after the first await. Capability
validation still runs first so a forged or expired transaction cannot trigger
input inspection or sanitizer behavior. This preserves the invariant that the
stored, digested, delivered, verified, and applied values are the same bytes.

## 2026-07-18: Encrypt pair authority before durable replication

The BPC `secretHash` is an HMAC key used to authorize requests. Replicating it
as ordinary JSON would turn an outbox reader into a credential holder. Pair set
operations therefore seal the canonical authority payload with AES-256-GCM
before the database transaction and bind the ciphertext to the mutation
identity with authenticated additional data. Receiver opening is synchronous
and local so no key-service await occurs while database locks are held.

The pair tables and outbox are one authorization consistency boundary, so one
catalog attestation and one readiness capability cover both. A schema-version
advance without a structural migration would create false readiness; the v2 to
v3 path instead copies and validates legacy data, attests the final catalog,
and advances the marker atomically.
## 2026-07-18: Make pair registry lifecycle transitions atomic

Pair lifecycle changes now use an explicit `AtomicPairStore` capability because
detached read/mutate/write sequences can lose updates, resurrect revoked state,
double-consume approvals, and oversubscribe request or pair limits. PostgreSQL
couples each authoritative transition to its durable outbox mutation in one
SERIALIZABLE transaction. Compound approval and rotation mutations preserve the
same atomic boundary at the receiver. Legacy stores remain available only as a
bounded compatibility path; production construction can require the atomic
capability and fail closed.
