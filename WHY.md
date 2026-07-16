# Design Decisions

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
