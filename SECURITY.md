# BPC Protocol — Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.2.x   | ✅ Yes (current, IL4-7 hardened) |
| 0.1.x   | ❌ No (contains critical vulnerabilities — see below) |

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
| Layer 1 | ECDSA P-256 signature over canonical payload | Request tampering, replay attacks |
| Layer 2 | HKDF-SHA-256 derived HMAC (nonce + timestamp) | Secret-less signature forgery |
| Layer 3 | Argon2id (128 MiB, t=4) stored secret hash | Offline brute-force if DB is compromised |

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

### BPC-03 — HIGH: Weak Secret Hashing (SHA-256 instead of HKDF)

**CVSSv3:** 7.4 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N)

**Description:** `hashSecret()` in `packages/core/src/hmac.ts` used a single iteration of `SHA-256(bpc: + secret)` instead of the documented HKDF-SHA-256. This made the derived key trivially brute-forceable with GPU acceleration if the hash was exposed.

**Fix:** `hashSecret()` now uses `HKDF-SHA-256` with a fixed info label (`bpc-hmac-key-v1`) and a 256-bit output. The function throws on empty input.

**NIST SP 800-53 controls:** SC-13, IA-5.

---

### BPC-04 — HIGH: Unauthenticated Pair Enumeration

**CVSSv3:** 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Description:** The `/bpc/pairs` endpoint returned the full `StoredPair` object including `secretHash` and `pubJwk` to any unauthenticated caller, enabling offline brute-force attacks and targeted forgery.

**Fix:** Added `PairRegistry.listRedacted()` which strips `secretHash`, `pubJwk`, `failedSigs`, and `expiresAt` from the response. Server implementations **must** use `listRedacted()` for any HTTP-accessible listing endpoint.

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

## IL4/5/6/7 Compliance Summary

BPC Protocol v0.2.0 implements the following controls required for Impact Level 4–7 environments:

| Control Family | Control | Implementation |
|---------------|---------|----------------|
| **IA — Identification & Authentication** | IA-3 | ECDSA P-256 device authentication |
| | IA-5 | HKDF-SHA-256 key derivation; Argon2id (128 MiB, t=4) storage |
| | IA-5(1) | Secret policy: ≥16 chars, upper+lower+digit+2 special chars |
| **SC — System & Communications Protection** | SC-8 | Canonical payload integrity (tamper-evident serialization) |
| | SC-13 | FIPS-approved cryptography: ECDSA P-256, HMAC-SHA-256, HKDF-SHA-256, Argon2id |
| | SC-5 | DoS protection: rate limiting with capacity guard, input size limits |
| **SI — System & Information Integrity** | SI-10 | Input validation: method allowlist, pairId format, nonce UUID format, type validation |
| | SI-11 | Error handling: all error paths return structured results; no unhandled exceptions |
| | SI-3 | Prototype pollution prevention in canonical serialization |
| **AU — Audit & Accountability** | AU-2 | Structured audit log with action, severity, pairId, IP, method, path |
| | AU-3 | Extended audit fields: userAgent, requestId, severity |
| | AU-9 | Audit log ring buffer (10,000 entries); PostgreSQL backend available |
| | AU-12 | All verify_pass and verify_fail events logged |
| **AC — Access Control** | AC-2 | Pair lifecycle management (active/locked/revoked/rotated/expired) |
| | AC-3 | Scope enforcement (read/read-write/admin) per HTTP method |
| | AC-6 | Principle of least privilege: listRedacted() strips sensitive fields |

---

## Cryptographic Primitives

| Primitive | Algorithm | Key Size | Standard |
|-----------|-----------|----------|----------|
| Digital Signature | ECDSA P-256 | 256-bit | FIPS 186-4, NIST SP 800-186 |
| Key Derivation (HMAC key) | HKDF-SHA-256 | 256-bit output | NIST SP 800-56C Rev 2 |
| Message Authentication | HMAC-SHA-256 | 256-bit | FIPS 198-1 |
| Password Hashing | Argon2id | 128 MiB, t=4, p=4 | NIST SP 800-63B |
| Nonce Generation | UUID v4 (crypto.randomUUID) | 122-bit entropy | RFC 4122 |

---

## Deployment Recommendations for IL4-7

1. **Use Redis backends** (`RedisNonceStore`, `RedisRateLimiter`, `RedisAnomalyStore`) in production for distributed deployments.
2. **Use PostgreSQL backends** (`PgPairStore`, `PgAuditLog`) for persistent, auditable storage.
3. **Enable TLS 1.3** on all transport layers (BPC does not provide transport security).
4. **Set `expiresAt`** on all pairs to enforce credential rotation schedules.
5. **Monitor `threatScore()`** from `AnomalyEngine` and alert on scores > 1000.
6. **Restrict `/bpc/pairs`** to authenticated admin users using `listRedacted()`.
7. **Use dual-track rate limiting**: separate `MemoryRateLimiter` instances for IP-based and pairId-based limits.
