# Changelog

All notable changes to BPC Protocol are documented in this file.

## [Unreleased] -- 2026-07-15

- Authenticated HA mutation envelopes now bind source, sequence, timestamp, and
  operation; receivers reject tampering, expiry, gaps, stale resurrection, and
  same-sequence conflicts.
- Principal session proofs bind requested authorization and runtime metadata;
  effective authority comes from a server resolver, proof nonces are one-use,
  and fallback verification uses an atomic nonce backend.
- Request verification now binds pair ID, version, and mandatory full body
  hash before atomic nonce consumption. Shadow and ghost results are hard
  denials.
- Python and TypeScript now share HKDF parameters, full body hashes, canonical
  JWK fingerprints, and 64-byte P1363 ECDSA signatures. A real cross-language
  integration command runs both directions.
- Python registration sends the derived request key rather than the plaintext
  secret; Python key rotation now matches the signed v1.0 rotation contract.
- Reference revocation routes require admin authentication, and browser demos
  invoke the server instead of changing only local state.
- Npm publish manifests include compiled `dist` output and run prepack builds.
- CI actions and the Redis and PostgreSQL service images are pinned to immutable
  commits and content digests. CI now runs on the supported Node 24 LTS line.
- The Argon2 binding and Node type definitions were updated within the selected
  supported runtime baseline.
- Live Redis coverage now races 64 uses through two independent clients and
  requires exactly one first-use winner.
- PostgreSQL persistence now retains usage caps, ghost/canary identity, and
  cumulative failure state; a live test covers schema, pending records, CRUD,
  legacy-schema migration, and connection-restart durability.
- Active security and protocol documentation now separates implemented test
  propositions from production, authorization, hardware, FIPS, HA, and audit
  claims.

## [0.2.0] — 2026-05-18 — Security Hardening Release

This release remediates **two critical** and four high/medium vulnerabilities
identified during a full penetration test, stress test, and red team assessment.
Historical note corrected 2026-07-15: these changes are implementation and test
evidence only. They do not establish production readiness, compliance, FIPS
validation, or a DoD Impact Level authorization.

### Security Fixes

#### BPC-01 — CRITICAL: HMAC Authentication Bypass (CVSSv3 9.8)
- **`packages/core/src/hmac.ts`**: Removed the `return true` fallback in
  `verifySecretHmac()` that allowed authentication with an empty stored key.
  Empty or missing stored keys now unconditionally return `false`.
- **`packages/server/src/registry.ts`**: Added `validateRegistration()` which
  rejects `secretHash` shorter than 43 characters at registration time.
- **`packages/server/src/middleware.ts`**: Added explicit empty-`secretHash`
  check before calling `verifySecretHmac()` as defense-in-depth.

#### BPC-02 — CRITICAL: Rotation Endpoint DoS / Server Crash (CVSSv3 7.5)
- **`packages/server/src/rotation.ts`**: Moved `payload` declaration to outer
  scope to fix `ReferenceError: payload is not defined`. Added comprehensive
  input validation (size limits, type checks, timestamp window) and structured
  error returns on all paths. Server no longer crashes on any rotation request.

#### BPC-03 — HIGH: Weak Secret Hashing — SHA-256 instead of HKDF (CVSSv3 7.4)
- **`packages/core/src/hmac.ts`**: `hashSecret()` now uses `HKDF-SHA-256`
  with info label `bpc-hmac-key-v1` and 256-bit output. Throws on empty input.
  Previously used a single iteration of `SHA-256(bpc: + secret)`.

#### BPC-04 — HIGH: Unauthenticated Pair Enumeration (CVSSv3 5.3)
- **`packages/server/src/registry.ts`**: Added `listRedacted()` method that
  strips `secretHash`, `pubJwk`, `failedSigs`, and `expiresAt` from pair
  listings. Added `RedactedPair` type export.

#### BPC-05 — MEDIUM: `__proto__` Injection in Canonical Payload (CVSSv3 5.9)
- **`packages/core/src/canonical.ts`**: Rewrote to use `Object.create(null)`
  accumulator and explicitly throw `TypeError` on `__proto__`, `constructor`,
  and `prototype` keys. Nested object and array values are now rejected.
- **`packages/client-sdk/src/client.ts`**: Rotation payload now serializes
  `new_pub_jwk` as a JSON string (`new_pub_jwk_json`) to comply with the
  flat-scalar-only canonicalization requirement.
- **`packages/server/src/rotation.ts`**: Updated to parse `new_pub_jwk_json`
  from the signed payload.

#### BPC-06 — MEDIUM: Rate Limiter Memory Exhaustion (CVSSv3 5.3)
- **`packages/server/src/rate-limiter.ts`**: Added capacity guard that evicts
  the oldest 10% of keys when the map exceeds 50,000 entries.

### Additional Security Hardening

- **`packages/server/src/middleware.ts`**:
  - Added HTTP method allowlist (rejects `TRACE`, `CONNECT`, etc.).
  - Added `pairId` format validation (alphanumeric + `_-` only).
  - Added UUID v4 format validation for nonce before HMAC verification.
  - Added `Number.isFinite()` type check for timestamp (prevents type-confusion).
  - Removed `?? ''` fallback on `pair.secretHash` (defense-in-depth).

- **`packages/server/src/audit.ts`**:
  - Extended `AuditEntry` with `severity`, `userAgent`, and `requestId` fields.
  - Added `queryAll()` method for global audit trail access.
  - Increased `MemoryAuditLog` ring buffer from 1,000 to 10,000 entries.
  - Updated `PgAuditLog` schema with new columns and indexes.

- **`packages/core/src/secret.ts`**:
  - Increased `MIN_SECRET_LENGTH` from 8 to 16 characters.
  - Increased `MAX_SECRET_LENGTH` from 64 to 128 characters.
  - Increased Argon2id `memoryCost` from 64 MiB to 128 MiB.
  - Increased Argon2id `timeCost` from 3 to 4 iterations.
  - Strengthened password policy: now requires at least 2 special characters.

### New Files

- **`SECURITY.md`**: Security policy, vulnerability history, preliminary
  compliance matrix, and deployment recommendations.
- **`packages/server/tests/security.test.ts`**: 37 adversarial tests covering
  the six named findings and input-validation requirements.

### Test Results

```
@bpc/core      — 23/23 tests pass
@bpc/server    — 63/63 tests pass (37 new adversarial security tests)
@bpc/client-sdk — 8/8 tests pass
Total          — 94/94 tests pass
```

### Breaking Changes

- `validateSecret()` now requires ≥ 16 characters and ≥ 2 special characters.
  Existing secrets shorter than 16 characters will fail validation.
- `canonicalize()` now throws on nested objects and forbidden keys.
  Rotation payloads must use `new_pub_jwk_json` (string) instead of `new_pub_jwk` (object).
- `verifySecretHmac()` no longer has a fallback for empty stored keys.
  All pairs must have a valid `secretHash` derived via `hashSecret()`.

---

## [0.1.0] — Initial Release

Initial implementation of BPC Protocol with ECDSA P-256 + HMAC + Argon2id.

> **⚠️ WARNING:** v0.1.0 contains critical security vulnerabilities (BPC-01, BPC-02, BPC-03).
> Do not use v0.1.0 in any environment. Upgrade to v0.2.0 immediately.
