# BPC Protocol Specification v1.0

## 1. Abstract

Bound Pair Credentials (BPC) is a request authentication protocol that binds API access to a specific device key, a registered pair identity, and a user-chosen secret. Every request is individually signed, timestamped, and nonce-protected, making stolen credentials unusable without simultaneous possession of all factors. This document specifies the key generation, pairing, request signing, and verification procedures for BPC v1.0.

## 2. Status

**v1.0** -- not an IETF or W3C standard. Patent pending.

This specification describes the protocol as implemented in the `@bpc/core`, `@bpc/server`, and `@bpc/client-sdk` reference packages. Normative behavior is defined by this document; the reference implementation is illustrative.

### Changes from v0.1.0
- Secret hashing upgraded from SHA-256 to Argon2id for server-side storage
- Minimum secret length increased from 4 to 8 characters
- HMAC output is now full 256-bit (43 base64url chars), not truncated to 16 chars
- Protocol version field added to canonical payload
- Scope enforcement is now mandatory in the verification pipeline
- Body hash verification is now mandatory
- Pair lockout after configurable failure threshold
- Pair expiry with configurable TTL
- Rate limiting specification added
- Standardized error format defined
- Audit logging requirements defined
- Persistent storage interfaces defined (PostgreSQL + Redis reference implementations)

## 3. Terminology

**Box** -- A BPC-enabled server instance. The box holds the pair registry, nonce store, anomaly engine, and audit log. It verifies all incoming BPC-signed requests.

**Pair** -- A registered relationship between a client and a box. Each pair has a unique ID, a scope, a mode, a public key, and a secret hash. A pair must be explicitly created and approved before the client can make requests.

**Device Key** -- An ECDSA P-256 keypair generated on the client device via the Web Crypto API with the `extractable` flag set to `false`. The private key cannot be read by JavaScript. The public key is registered with the box during pairing.

**Pair ID** -- A server-generated identifier (prefixed `pair_`) assigned to an approved pair. Included in every signed request via the `X-BPC-Pair-ID` header.

**User Secret** -- An 8-64 character string chosen by the client at pairing time. Must contain at least one uppercase letter, one lowercase letter, one digit, and one symbol. The secret is mixed into every request signature via HMAC derivation. It is never stored in plaintext on the server, never transmitted in cleartext, and never logged.

**Secret Hash** -- An Argon2id hash of the user secret, computed server-side at pairing time. The client sends the plaintext secret over TLS during registration only; the server hashes it immediately and discards the plaintext. The Argon2id parameters are: memory=65536 (64 MB), timeCost=3, parallelism=4.

**HMAC Secret** -- For per-request signing, the client computes `HMAC-SHA-256(secret, nonce + timestamp)` using the plaintext secret as the HMAC key. The full 256-bit output (43 base64url characters) is included in the canonical payload. This is distinct from the Argon2id storage hash.

**Canonical Payload** -- A flat JSON object containing the fields required for request signing, including a protocol version field. Keys are sorted alphabetically. The JSON serialization of this object is the data that is signed by the device key.

**Signing Window** -- The maximum allowable clock skew between client and server, in milliseconds. Requests with a timestamp outside `now ± sigWindowMs` are rejected. Default: 60,000ms (60 seconds).

**Nonce Store** -- A server-side data structure that tracks recently seen nonces. Each nonce can be used exactly once. Entries expire after `2 × sigWindowMs` milliseconds. Production deployments MUST use a shared store (e.g., Redis) for multi-instance deployments.

## 4. Protocol Overview

BPC replaces static API keys with a multi-factor, per-request signing protocol. A client generates a device-bound keypair, pairs with a server (the "box"), and then signs every request using the private key, a user-chosen secret, a fresh nonce, and a timestamp. The server verifies all factors before processing the request. Stolen credentials are useless without the device key, the user secret, and a fresh nonce window.

```
Client                                     Server (Box)
  |                                            |
  |--- 1. Generate ECDSA P-256 keypair ------->|
  |--- 2. Submit registration request -------->|
  |        (name, scope, mode, secret, pubJwk) |
  |                                            |--- 3. Hash secret (Argon2id)
  |                                            |--- 4. Store pending pair
  |                                            |--- 5. Owner approves
  |<-- 6. Return pairId ----------------------|
  |                                            |
  |  (per request)                             |
  |--- 7. Build canonical payload (v1.0) ----->|
  |--- 8. HMAC-derive secret into payload ---->|
  |--- 9. ECDSA-sign canonical payload ------->|
  |--- 10. Send request + BPC headers -------->|
  |                                            |--- 11. Rate limit check
  |                                            |--- 12. Verify (12-step pipeline)
  |                                            |--- 13. Audit log write
  |<-- 14. Response --------------------------|
```

## 5. Key Generation

The client generates an ECDSA keypair using the Web Crypto API:

- **Algorithm**: ECDSA with named curve P-256
- **Extractable**: `false` -- the private key cannot be exported via `crypto.subtle.exportKey()`
- **Key usages**: `['sign', 'verify']`
- **Public key export**: The public key is exported as JWK for transmission to the server

The public key fingerprint is computed as `base64url(SHA-256(JSON.stringify(pubJwk))).substring(0, 20)`.

**Limitation**: The `non-extractable` flag prevents JavaScript-level extraction of the private key. It does not provide hardware-level key binding. An attacker with full control of the browser process (e.g., via a compromised extension or memory dump) may be able to extract the key at a lower level. Hardware-bound key protection requires platform attestation (e.g., WebAuthn with a TPM or Secure Enclave), which is specified as an optional extension in Section 16.

## 6. Pairing Flow

1. **Client generates keypair** -- calls `generateKeypair()`, which produces an ECDSA P-256 keypair with `extractable: false`.
2. **Client submits registration request** -- sends `{ name, scope, mode, secret, pubJwk }` to the server's pairing endpoint over TLS. The plaintext secret is transmitted only in this request.
   - `name`: human-readable label for the pair (e.g., "Ron's laptop")
   - `scope`: one of `read`, `read-write`, `admin`
   - `mode`: one of `development`, `production`
   - `secret`: the user-chosen secret (8-64 chars, complexity requirements enforced)
   - `pubJwk`: the exported public key in JWK format
3. **Server hashes secret** -- computes `argon2id(secret)` with the specified parameters and stores the hash. The plaintext secret is discarded immediately.
4. **Server stores pending pair** -- the server creates a pending approval record and returns an approval token.
5. **Owner approves** -- the box owner (or an automated policy in development mode) calls `approvePairing(token)`. In development mode, `registerDirect()` auto-approves.
6. **Server activates pair** -- the server generates a `pair_`-prefixed ID, stores the pair record (with `status: active`), and returns the pair ID to the client.
7. **Client stores pair ID + keypair** -- the client persists the pair ID and the CryptoKey references (IndexedDB in browser, encrypted keyfile in Node.js).

The server stores: pair ID, name, scope, mode, Argon2id secret hash, public key (JWK), status, creation timestamp, expiry timestamp (optional), activity counters. The server never stores the plaintext user secret.

## 7. Request Signing

For each API request, the client constructs and signs a canonical payload:

1. **Generate nonce** -- `crypto.randomUUID()`.
2. **Capture timestamp** -- `Date.now()` (Unix milliseconds).
3. **Compute body hash** -- `"sha256:" + base64url(SHA-256(body)).substring(0, 32)`. For requests with no body, use the SHA-256 hash of the empty string.
4. **Derive secret HMAC** -- `base64url(HMAC-SHA-256(secret, nonce + timestamp))`. The user's plaintext secret is the HMAC key; the concatenation of nonce and timestamp (as strings) is the message. The full 256-bit HMAC output is used (43 base64url characters).
5. **Build canonical payload** -- construct the `BPCCanonicalPayload` object (see Section 9), including `version: "1.0"`.
6. **Canonicalize** -- serialize the payload as JSON with keys sorted alphabetically.
7. **Sign** -- `base64url(ECDSA-SHA-256(privateKey, canonicalized_json))`.
8. **Encode signed data** -- `base64url(UTF-8(canonicalized_json))`.
9. **Attach headers** -- set `X-BPC-Pair-ID`, `X-BPC-Signature`, `X-BPC-Signed-Data`, and `X-BPC-Version` on the HTTP request.

## 8. Request Verification (Server)

The server executes a 12-step verification pipeline. Every step must pass. Failure at any step returns a standardized error (see Section 15).

1. **Rate limit check** -- check per-pair, per-IP, and global rate limits. If exceeded, return `rate_limited` with `Retry-After` header.

2. **Headers present** -- verify that `X-BPC-Pair-ID`, `X-BPC-Signature`, `X-BPC-Signed-Data`, and `X-BPC-Version` are all present. Error: `missing_headers`.

3. **Pair exists and is active** -- look up the pair ID in the registry. If the pair does not exist, record an unknown-pair probe in the anomaly engine. Error: `unknown_pair`. If the pair exists but has status `revoked`, error: `pair_revoked`. If the pair has expired (`expiresAt < now`), error: `pair_expired`.

4. **Pair not locked out** -- if `pair.failedSigs >= config.lockoutCount`, error: `pair_locked_out`. The pair must be manually unlocked by the box owner.

5. **Decode and parse canonical payload** -- base64url-decode `X-BPC-Signed-Data` and parse the result as JSON. Error: `invalid_signed_data`.

6. **Protocol version check** -- verify `payload.version === '1.0'`. Error: `unsupported_version`.

7. **Timestamp within window** -- verify `|now - payload.timestamp| <= sigWindowMs`. Error: `timestamp_expired`.

8. **Nonce not seen before** -- check the nonce store. If the nonce has been seen, the request is a replay. Error: `replay_detected`.

9. **Method and path match** -- verify `payload.method === request.method` and `payload.path === request.path`. Error: `method_path_mismatch`.

10. **Body hash match** -- if the request has a body, compute `SHA-256(body)` and verify it matches `payload.body_hash`. Error: `body_hash_mismatch`.

11. **Verify ECDSA signature** -- import the pair's registered public key (JWK), canonicalize the payload, and verify the ECDSA-SHA-256 signature. Error: `signature_invalid`.

12. **Scope enforcement** -- verify the pair's scope allows the HTTP method:
    - `read`: GET, HEAD, OPTIONS only
    - `read-write`: GET, HEAD, OPTIONS, POST, PUT, PATCH
    - `admin`: all methods including DELETE
    Error: `scope_denied`.

13. **All checks passed** -- record successful activity on the pair. Write audit log entry. Return `{ ok: true, pairId, pair }`.

At every failure step, the anomaly engine's counters are incremented (both global and per-pair). An audit log entry is written for every verification result.

## 9. Canonical Payload

The canonical payload is a flat JSON object with exactly these fields:

| Field | Type | Description |
|-------|------|-------------|
| `body_hash` | string | `"sha256:" + base64url(SHA-256(body)).substring(0, 32)`, or the hash of empty string for bodyless requests |
| `method` | string | HTTP method, uppercase (e.g., `"GET"`, `"POST"`) |
| `nonce` | string | `crypto.randomUUID()` -- unique per request |
| `pair_id` | string | The registered pair ID |
| `path` | string | The request path (e.g., `"/api/data"`) |
| `secret_hmac` | string | `base64url(HMAC-SHA-256(secret, nonce + timestamp))` -- full 256-bit output (43 chars) |
| `timestamp` | number | `Date.now()` -- Unix milliseconds |
| `version` | string | Protocol version, currently `"1.0"` |

**Sorting rule**: keys are sorted in ascending alphabetical order. The object is flat (no nested objects or arrays). The canonical form is `JSON.stringify(sorted_object)`.

This ordering is deterministic: `body_hash`, `method`, `nonce`, `pair_id`, `path`, `secret_hmac`, `timestamp`, `version`.

## 10. Anti-Replay Mechanism

BPC prevents replay attacks through two complementary mechanisms:

1. **Nonce uniqueness** -- every request includes a `crypto.randomUUID()` nonce. The server's nonce store tracks all nonces seen within the active window. If a nonce has already been consumed, the request is rejected with `replay_detected`.

2. **Timestamp window** -- every request includes a `Date.now()` timestamp. The server rejects requests where `|server_time - request_timestamp| > sigWindowMs`. Default `sigWindowMs` is 60,000ms (60 seconds).

**Nonce store TTL**: nonces are retained for `2 × sigWindowMs` plus a 10-second buffer (default: 130,000ms). This ensures that a nonce cannot be reused even if the original request arrived at the edge of the timestamp window and accounts for minor processing delays.

**Eviction**: the nonce store performs lazy eviction on each lookup, removing entries whose expiry timestamp has passed. In Redis-backed deployments, key expiry is handled natively by Redis TTL.

**Multi-instance**: production deployments behind a load balancer MUST use a shared nonce store (e.g., Redis) to prevent replay attacks that target different server instances.

## 11. Behavioral Anomaly Detection

The anomaly engine tracks both global and per-pair counters within a sliding 1-hour window:

| Counter | Incremented when |
|---------|-----------------|
| `unknownPairProbes` | A request references a pair ID not in the registry |
| `sigFailures` | ECDSA signature verification fails |
| `replayAttempts` | A nonce has already been consumed |
| `expiredTimestamps` | Timestamp is outside the signing window |
| `scopeDenials` | Pair scope does not allow the requested method |
| `totalRequests` | Any request enters the verification pipeline |
| `deniedRequests` | Any verification step fails |

**Threat score formula**:

```
unknownRate  = min(unknownPairProbes / max(totalRequests, 1), 1)
sigRate      = min(sigFailures       / max(totalRequests, 1), 1)
replayRate   = min(replayAttempts    / max(totalRequests, 1), 1)
expiredRate  = min(expiredTimestamps / max(totalRequests, 1), 1)

threatScore  = round((unknownRate * 30 + sigRate * 30 + replayRate * 20 + expiredRate * 20) * 100)
```

The threat score ranges from 0 (no anomalies) to 100 (all requests are attacks). Counters decay: in Redis-backed deployments, each counter key has a 1-hour TTL. In memory-backed deployments, counters are reset hourly.

## 12. Step-Up Approval

In `production` mode, sensitive operations require real-time owner approval before the server processes them:

- **Sensitive operations**: HTTP methods `DELETE` and `PUT` to paths matching `/billing` or `/admin`
- **Approval flow**: the server notifies the box owner (via webhook, WebSocket, or push notification) with a configurable timeout (default: 30 seconds). The owner can approve or deny. If the timeout expires, the request is denied.
- **Development mode**: step-up approval is bypassed -- requests proceed without owner intervention.

Step-up approval is an application-layer concern implemented above the BPC verification pipeline. A request must first pass all 12 verification steps before step-up approval is triggered.

## 13. Rate Limiting

BPC defines three rate limit tiers:

| Tier | Default | Scope |
|------|---------|-------|
| Per-pair | 100 requests/minute | Individual pair ID |
| Per-IP | 200 requests/minute | Source IP address |
| Global | 10,000 requests/minute | All requests to the box |

Rate limiting is checked BEFORE signature verification (step 1 in the pipeline) because it is computationally cheaper than ECDSA verification.

The recommended algorithm is sliding window (sorted set in Redis, or timestamp array in memory). When a rate limit is exceeded, the server returns HTTP 429 with `Retry-After` header indicating seconds until the window resets.

## 14. Pair Lifecycle

### Pair States
- `pending` -- awaiting owner approval
- `active` -- approved, can make requests
- `locked` -- temporarily locked due to excessive failures (requires manual unlock)
- `expired` -- TTL exceeded (requires rotation or re-registration)
- `rotated` -- replaced by a new pair (kept for audit trail)
- `revoked` -- permanently deactivated

### Pair Expiry
Pairs may have an optional `expiresAt` timestamp. When set, the server rejects requests from expired pairs with `pair_expired`. Expiry is checked during verification (step 3).

### Pair Rotation
A client may rotate its keypair without re-registering:
1. Client generates a new ECDSA P-256 keypair
2. Client sends a rotation request signed by the OLD private key, containing the new public key JWK
3. Server verifies the old signature (proves possession of old key)
4. Server creates a new pair record with the new public key, same scope/mode/secretHash
5. Server marks the old pair as `rotated`
6. Server returns the new pair ID

This allows key rotation without interrupting service and without requiring the owner to re-approve.

## 15. Error Format

All BPC verification failures return a standardized JSON error:

```json
{
  "error": "machine_readable_code",
  "message": "Human-readable description",
  "pairId": "pair_xxx (if applicable)",
  "retryAfter": 30
}
```

| Error Code | HTTP Status | Description |
|------------|-------------|-------------|
| `missing_headers` | 401 | Required BPC headers not present |
| `unknown_pair` | 401 | Pair ID not in registry |
| `pair_revoked` | 403 | Pair has been revoked |
| `pair_locked_out` | 403 | Pair locked due to excessive failures |
| `pair_expired` | 403 | Pair TTL exceeded |
| `invalid_signed_data` | 400 | Signed data is malformed |
| `unsupported_version` | 400 | Protocol version not supported |
| `timestamp_expired` | 401 | Timestamp outside allowed window |
| `replay_detected` | 401 | Nonce already consumed |
| `method_path_mismatch` | 401 | Method or path doesn't match signed payload |
| `body_hash_mismatch` | 401 | Body hash doesn't match signed payload |
| `signature_invalid` | 401 | ECDSA signature verification failed |
| `scope_denied` | 403 | Pair scope doesn't allow this operation |
| `rate_limited` | 429 | Rate limit exceeded |

## 16. Security Considerations

### What BPC protects against

| Attack | How BPC stops it |
|--------|-----------------|
| Stolen API key | The key alone is useless -- the attacker has no device key to sign requests |
| Wrong device | The ECDSA private key is non-extractable and bound to the generating device's Web Crypto context |
| Wrong user secret | The secret HMAC is mixed into the canonical payload and covered by the ECDSA signature |
| Replay attack | Nonce uniqueness + timestamp window; nonces stored in shared persistent store |
| Probing / enumeration | Unknown pair IDs tracked by anomaly engine; rate limiting blocks excessive probes |
| Supply-chain attack | Stolen API key from malicious code cannot be used from attacker's device |
| Brute-force secret | Server-side Argon2id hash is intentionally slow (64MB, 3 iterations); minimum 8-char secret |

### What BPC does NOT protect against

| Attack | Why |
|--------|-----|
| Full browser compromise (TPM-less) | Attacker with code execution can invoke `crypto.subtle.sign()` in-memory. Mitigated by WebAuthn attestation (Section 17). |
| Server database breach | Attacker obtains public keys and Argon2id hashes. Cannot forge signatures. Weak secrets with <8 chars are mitigated by enforced minimum length. |
| Side-channel attacks | Timing attacks, cache attacks, power analysis depend on underlying crypto implementations. |
| Compromised server | BPC is a client-authentication protocol; it does not protect against a malicious server. |
| TLS interception (MITM) | BPC signs the payload, not the transport. The client SDK enforces HTTPS for non-local servers. |

## 17. HTTP Headers

BPC defines four HTTP request headers:

| Header | Type | Description |
|--------|------|-------------|
| `X-BPC-Pair-ID` | string | The registered pair identifier (e.g., `pair_a1b2c3d4e5f6g7h8`) |
| `X-BPC-Signature` | string | base64url-encoded ECDSA-SHA-256 signature over the canonicalized payload |
| `X-BPC-Signed-Data` | string | base64url-encoded UTF-8 of the canonical payload JSON |
| `X-BPC-Version` | string | Protocol version (currently `"1.0"`) |

All four headers are required on every BPC-authenticated request. Absence of any header results in immediate rejection (`missing_headers`).

## 18. WebAuthn Extension (Optional)

For hardware-bound key protection, the client uses WebAuthn platform attestation:

1. Client calls `navigator.credentials.create()` with `authenticatorSelection: { authenticatorAttachment: 'platform' }`
2. Server verifies the attestation response, confirming the key is backed by a TPM or Secure Enclave
3. The attestation certificate chain is stored alongside the pair record
4. On each request, the server may optionally require a fresh WebAuthn assertion

This extension is optional in v1.0 and RECOMMENDED for production deployments handling sensitive data.

## 19. Audit Logging

All BPC verification events MUST be logged to a durable audit store:

| Event Type | When |
|------------|------|
| `auth_success` | Verification pipeline passes all steps |
| `auth_failure` | Any verification step fails |
| `pair_created` | New pair registered and approved |
| `pair_revoked` | Pair manually revoked |
| `pair_rotated` | Pair keypair rotated |
| `pair_expired` | Pair TTL exceeded |
| `rate_limited` | Rate limit check failed |
| `lockout` | Pair locked due to excessive failures |

Each audit entry includes: timestamp, event type, pair ID (if applicable), source IP, HTTP method, path, error code (if failure), and optional metadata.

Audit logs MUST be retained for a minimum of 90 days. The storage backend must be append-only or tamper-evident for compliance purposes.

## 20. Persistence Requirements

### Pair Registry
Production deployments MUST use a durable store (e.g., PostgreSQL) for the pair registry. The in-memory store is suitable only for development and testing.

### Nonce Store
Production deployments MUST use a shared persistent store (e.g., Redis) for nonces. The key TTL should be `2 × sigWindowMs + 10000ms` (default: 130 seconds). In-memory nonce stores are not suitable for multi-instance deployments.

### Anomaly Counters
Counter storage should match the nonce store backend (e.g., Redis) with 1-hour sliding window TTLs.

## 21. Protocol Versioning

The protocol version is included in the canonical payload (`version` field) and in the `X-BPC-Version` header. This prevents:

- **Version downgrade attacks** -- an attacker cannot replay a request signed with an older protocol version that has weaker security properties
- **Silent breakage** -- when the signing algorithm or canonical format changes, mismatched versions are explicitly rejected

Servers MUST reject requests with unsupported versions. Servers MAY support multiple versions simultaneously during a transition period.
