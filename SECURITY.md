# BPC Protocol — Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | Yes (current beta line) |
| 0.1.x   | No (contains the vulnerabilities summarized below) |

---

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Report security issues privately via GitHub's [Security Advisories](https://github.com/rblake2320/bpc-protocol/security/advisories/new) feature.

We aim to acknowledge reports within **48 hours** and provide a fix within **14 days** for critical issues.

---

## Security Architecture

BPC Protocol implements a **three-layer authentication model**:

| Layer | Mechanism | Protects Against |
|-------|-----------|-----------------|
| Layer 1 | ECDSA P-256 signature over canonical payload | Request tampering and pair-key proof of possession |
| Layer 2 | HKDF-SHA-256 derived HMAC (nonce + timestamp) | Secret-less signature forgery |
| Optional storage helper | Argon2id (128 MiB, t=4) password hash | Reduces offline guessing risk for separately stored human-chosen secrets |

The live BPC request verifier stores an HKDF-SHA-256-derived HMAC key, not an
Argon2id password hash. The Argon2id helper is a separate API and must not be
described as part of request signing or verification.

---

## Vulnerability History (v0.1.0 → v0.2.0)

The following vulnerabilities were identified via penetration testing and remediated in v0.2.0.

### BPC-01 — CRITICAL: HMAC Authentication Bypass

**CVSSv3:** 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Description:** `verifySecretHmac()` in `packages/core/src/hmac.ts` contained a fallback that returned `true` when the stored key was empty or missing. An attacker who registered a pair with an empty `secretHash` could authenticate any request without knowing the secret.

**Fix:** Removed the fallback. Empty or missing stored keys now unconditionally return `false`. Defense-in-depth: `PairRegistry.validateRegistration()` rejects registration with `secretHash` shorter than 43 characters, and `verifyBPCRequest()` explicitly rejects pairs with empty `secretHash` before calling `verifySecretHmac()`.

**NIST SP 800-53 controls:** IA-5, IA-3.

---

### BPC-02 — CRITICAL: Rotation Endpoint DoS (Server Crash)

**CVSSv3:** 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)

**Description:** `handleRotation()` in `packages/server/src/rotation.ts` declared `payload` inside a `try{}` block but referenced it after the block, causing an unhandled `ReferenceError: payload is not defined` that crashed the entire Node.js server process on every valid rotation request.

**Fix:** `payload` is now declared in the outer scope before the `try{}` block. All error paths return a structured `RotationResult` instead of throwing. Input size limits (4096 bytes for `signedData`, 200 bytes for `signature`) prevent oversized-payload DoS.

**NIST SP 800-53 controls:** SI-11, SC-5.

---

### BPC-03 — HIGH: Undomain-separated Request-Key Derivation

**CVSSv3:** 7.4 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N)

**Description:** `hashSecret()` in `packages/core/src/hmac.ts` used a direct
SHA-256 construction that did not match the documented, domain-separated
request-key derivation. Direct SHA-256 and HKDF are both fast; neither is a
password-hardening KDF.

**Fix:** `hashSecret()` now uses `HKDF-SHA-256` with protocol-specific salt
`bpc-protocol-hmac-salt-v1`, info `bpc-v1-hmac-key`, and a 256-bit output. The
function throws on empty input. Reference registration helpers separately
enforce the project secret policy before deriving this key.

**NIST SP 800-53 controls:** SC-13, IA-5.

---

### BPC-04 — HIGH: Unauthenticated Pair Enumeration

**CVSSv3:** 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Description:** The `/bpc/pairs` endpoint returned the full `StoredPair` object including `secretHash` and `pubJwk` to any unauthenticated caller, enabling offline brute-force attacks and targeted forgery.

**Fix:** Added `PairRegistry.listRedacted()` which strips `secretHash`, `pubJwk`,
`failedSigs`, and `expiresAt`. Pair listing remains administrative metadata and
must still require authorization; redaction is defense in depth, not a public
access policy.

**NIST SP 800-53 controls:** AC-3, AC-6.

---

### BPC-05 — MEDIUM: `__proto__` Injection in Canonical Payload

**CVSSv3:** 5.9 (AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N)

**Description:** `canonicalize()` in `packages/core/src/canonical.ts` used a standard `{}` accumulator. When a payload contained a `__proto__` key (valid JSON), `for...in` enumeration silently dropped it, creating a signature verification bypass where the signed payload differed from what the server processed.

**Fix:** `canonicalize()` now uses `Object.create(null)` (null-prototype accumulator) and explicitly throws `TypeError` on `__proto__`, `constructor`, and `prototype` keys. Nested object values are also rejected to prevent further injection vectors. Rotation payloads now serialize `new_pub_jwk` as a JSON string (`new_pub_jwk_json`) to comply with the flat-scalar-only requirement.

**NIST SP 800-53 controls:** SI-10, SI-3.

---

### BPC-06 — MEDIUM: Rate Limiter Memory Exhaustion

**CVSSv3:** 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L)

**Description:** `MemoryRateLimiter` had no upper bound on the number of tracked keys. An attacker could exhaust server memory by sending requests from millions of unique IPs.

**Fix:** Added a capacity guard that evicts the oldest 10% of entries when the map exceeds 50,000 keys. Documentation updated to recommend dual-track rate limiting (separate IP-based and pairId-based limiters).

**NIST SP 800-53 controls:** SC-5.

---

## Preliminary Control Mapping

The following mappings identify candidate implementation evidence for assessor
review. They do not establish compliance, a FIPS validation, a DoD Impact Level,
or an authorization. There is no current DoD Cloud Computing SRG IL7.

| Control Family | Control | Implementation |
|---------------|---------|----------------|
| **IA — Identification & Authentication** | IA-3 | ECDSA P-256 pair-key authentication |
| | IA-5 | HKDF-SHA-256 request-key derivation; optional Argon2id storage helper |
| | IA-5(1) | Secret policy: ≥16 chars, upper+lower+digit+2 special chars |
| **SC — System & Communications Protection** | SC-8 | Canonical payload integrity (tamper-evident serialization) |
| | SC-13 | ECDSA P-256, HMAC-SHA-256, and HKDF-SHA-256 algorithm use; deployed module validation is external evidence |
| | SC-5 | DoS protection: rate limiting with capacity guard, input size limits |
| **SI — System & Information Integrity** | SI-10 | Input validation: method allowlist, pairId format, nonce UUID format, type validation |
| | SI-11 | Error handling: all error paths return structured results; no unhandled exceptions |
| | SI-3 | Prototype pollution prevention in canonical serialization |
| **AU — Audit & Accountability** | AU-2 | Structured audit log with action, severity, pairId, IP, method, path |
| | AU-3 | Extended audit fields: userAgent, requestId, severity |
| | AU-9 | Hash-chained audit entries and PostgreSQL mutation-denial schema; deployment protection and external anchoring remain required |
| | AU-12 | All verify_pass and verify_fail events logged |
| **AC — Access Control** | AC-2 | Pair lifecycle management (active/locked/revoked/rotated/expired) |
| | AC-3 | Closed scope enforcement (read/read-write/admin) at TypeScript and Python intake and per HTTP method |
| | AC-6 | Principle of least privilege: listRedacted() strips sensitive fields |

TypeScript callers must authorize from `result.snapshot` only after checking
`result.ok === true`. The snapshot is frozen and is derived from the same
point-in-time registry read used by request verification. The verifier does not
serve an unauthenticated health exception; health routes belong outside the
authorization middleware. A revocation that races a request already in flight
requires a deployment-specific authorization version fence if cancellation of
that request is required.

---

## Cryptographic Primitives Requested By The Code

| Primitive | Algorithm | Use |
|-----------|-----------|-----|
| Digital signature | ECDSA P-256 via the runtime provider | Pair request signatures |
| Key derivation | HKDF-SHA-256 via the runtime provider | Request HMAC key derivation |
| Message authentication | HMAC-SHA-256 via the runtime provider | Nonce/timestamp secret binding |
| Optional password hashing helper | Argon2id with project-configured parameters | Optional secret storage helper |
| Nonce generation | `crypto.randomUUID()` | Per-request replay identifier |

---

Algorithm selection does not make a product or deployment FIPS validated. FIPS
140 status requires the exact cryptographic module, version, approved mode, and
operating environment to appear in applicable CMVP evidence.

## Deployment Recommendations

1. **Use `createRedisBackedNonceStore()`** for distributed TypeScript replay
   protection. Require an explicit namespace, `noeviction`, bounded client
   deadlines, and deny on every uncertain Redis result. Never fall back to a
   process-local nonce store. If failover may have lost nonce writes, quarantine
   authorization for the full derived retention interval.
2. **Use PostgreSQL backends** (`PgPairStore`, `PgAuditLog`) for persistent, auditable storage.
3. **Enable TLS 1.3** on all transport layers (BPC does not provide transport security).
4. **Set `expiresAt`** on all pairs to enforce credential rotation schedules.
5. **Monitor `threatScore()`** from `AnomalyEngine` and set a deployment policy within its 0-100 range; the built-in attack verdict threshold is 70.
6. **Restrict `/bpc/pairs`** to authenticated admin users and return only `listRedacted()` data.
7. **Use dual-track rate limiting**: separate `MemoryRateLimiter` instances for IP-based and pairId-based limits.
