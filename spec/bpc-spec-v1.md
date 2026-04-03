# BPC Protocol Specification v0.1.0

## 1. Abstract

Bound Pair Credentials (BPC) is a request authentication protocol that binds API access to a specific device key, a registered pair identity, and a user-chosen secret. Every request is individually signed, timestamped, and nonce-protected, making stolen credentials unusable without simultaneous possession of all factors. This document specifies the key generation, pairing, request signing, and verification procedures for BPC v0.1.0.

## 2. Status

**DRAFT v0.1.0** -- not an IETF or W3C standard. Patent pending.

This specification describes the protocol as implemented in the `@bpc/core`, `@bpc/server`, and `@bpc/client-sdk` reference packages. Normative behavior is defined by this document; the reference implementation is illustrative.

## 3. Terminology

**Box** -- A BPC-enabled server instance. The box holds the pair registry, nonce store, and anomaly engine. It verifies all incoming BPC-signed requests.

**Pair** -- A registered relationship between a client and a box. Each pair has a unique ID, a scope, a mode, a public key, and a secret hash. A pair must be explicitly created and approved before the client can make requests.

**Device Key** -- An ECDSA P-256 keypair generated on the client device via the Web Crypto API with the `extractable` flag set to `false`. The private key cannot be read by JavaScript. The public key is registered with the box during pairing.

**Pair ID** -- A server-generated identifier (prefixed `pair_`) assigned to an approved pair. Included in every signed request via the `X-BPC-Pair-ID` header.

**User Secret** -- A 4-12 character string chosen by the client at pairing time. The secret is mixed into every request signature via HMAC derivation. It is never stored in plaintext on the server, never transmitted in cleartext, and never logged.

**Secret Hash** -- `base64url(SHA-256("bpc:" + secret))`. Computed by the client and sent to the server during registration. The server stores this hash, not the plaintext secret.

**Canonical Payload** -- A flat JSON object containing the fields required for request signing. Keys are sorted alphabetically. The JSON serialization of this object is the data that is signed by the device key.

**Signing Window** -- The maximum allowable clock skew between client and server, in milliseconds. Requests with a timestamp outside `now +/- sigWindowMs` are rejected. Default: 60,000ms (60 seconds).

**Nonce Store** -- A server-side data structure that tracks recently seen nonces. Each nonce can be used exactly once. Entries expire after `2 * sigWindowMs` milliseconds.

## 4. Protocol Overview

BPC replaces static API keys with a multi-factor, per-request signing protocol. A client generates a device-bound keypair, pairs with a server (the "box"), and then signs every request using the private key, a user-chosen secret, a fresh nonce, and a timestamp. The server verifies all factors before processing the request. Stolen credentials are useless without the device key, the user secret, and a fresh nonce window.

```
Client                                     Server (Box)
  |                                            |
  |--- 1. Generate ECDSA P-256 keypair ------->|
  |--- 2. Hash user secret ------------------->|
  |--- 3. Submit registration request -------->|
  |                                            |--- 4. Store pending pair
  |                                            |--- 5. Owner approves
  |<-- 6. Return pairId ----------------------|
  |                                            |
  |  (per request)                             |
  |--- 7. Build canonical payload ------------>|
  |--- 8. HMAC-derive secret into payload ---->|
  |--- 9. ECDSA-sign canonical payload ------->|
  |--- 10. Send request + BPC headers -------->|
  |                                            |--- 11. Verify (8-step pipeline)
  |<-- 12. Response --------------------------|
```

## 5. Key Generation

The client generates an ECDSA keypair using the Web Crypto API:

- **Algorithm**: ECDSA with named curve P-256
- **Extractable**: `false` -- the private key cannot be exported via `crypto.subtle.exportKey()`
- **Key usages**: `['sign', 'verify']`
- **Public key export**: The public key is exported as JWK for transmission to the server

The public key fingerprint is computed as `base64url(SHA-256(JSON.stringify(pubJwk))).substring(0, 20)`.

**Limitation**: The `non-extractable` flag prevents JavaScript-level extraction of the private key. It does not provide hardware-level key binding. An attacker with full control of the browser process (e.g., via a compromised extension or memory dump) may be able to extract the key at a lower level. Hardware-bound key protection requires platform attestation (e.g., WebAuthn with a TPM or Secure Enclave), which is not covered in v0.1.0.

## 6. Pairing Flow

1. **Client generates keypair** -- calls `generateKeypair()`, which produces an ECDSA P-256 keypair with `extractable: false`.
2. **Client computes secret hash** -- `secretHash = base64url(SHA-256("bpc:" + secret))`.
3. **Client submits registration request** -- sends `{ name, scope, mode, secretHash, pubJwk }` to the server's pairing endpoint.
   - `name`: human-readable label for the pair (e.g., "Ron's laptop")
   - `scope`: one of `read`, `read-write`, `full`
   - `mode`: one of `development`, `production`
   - `secretHash`: the hashed user secret
   - `pubJwk`: the exported public key in JWK format
4. **Server stores pending pair** -- the server creates a pending approval record and returns an approval token.
5. **Owner approves** -- the box owner (or an automated policy in development mode) calls `approvePairing(token)`. In development mode, `registerDirect()` auto-approves.
6. **Server activates pair** -- the server generates a `pair_`-prefixed ID, stores the pair record (with `status: active`), and returns the pair ID to the client.
7. **Client stores pair ID + keypair** -- the client persists the pair ID and the CryptoKey references for future requests.

The server stores: pair ID, name, scope, mode, secret hash, public key (JWK), status, creation timestamp, activity counters. The server never receives or stores the plaintext user secret.

## 7. Request Signing

For each API request, the client constructs and signs a canonical payload:

1. **Generate nonce** -- `crypto.randomUUID()`.
2. **Capture timestamp** -- `Date.now()` (Unix milliseconds).
3. **Compute body hash** -- `"sha256:" + base64url(SHA-256(JSON.stringify(body))).substring(0, 32)`. For requests with no body, use the SHA-256 hash of the empty string.
4. **Derive secret HMAC** -- `base64url(HMAC-SHA-256(secret, nonce + timestamp)).substring(0, 16)`. The user's plaintext secret is the HMAC key; the concatenation of nonce and timestamp is the message.
5. **Build canonical payload** -- construct the `BPCCanonicalPayload` object (see Section 9).
6. **Canonicalize** -- serialize the payload as JSON with keys sorted alphabetically.
7. **Sign** -- `base64url(ECDSA-SHA-256(privateKey, canonicalized_json))`.
8. **Encode signed data** -- `base64url(UTF-8(canonicalized_json))`.
9. **Attach headers** -- set `X-BPC-Pair-ID`, `X-BPC-Signature`, and `X-BPC-Signed-Data` on the HTTP request.

## 8. Request Verification (Server)

The server executes an 8-step verification pipeline. Every step must pass. Failure at any step returns a specific error code.

1. **Headers present** -- verify that `X-BPC-Pair-ID`, `X-BPC-Signature`, and `X-BPC-Signed-Data` are all present. Error: `missing_headers`.

2. **Pair exists and is active** -- look up the pair ID in the registry. If the pair does not exist, record an unknown-pair probe in the anomaly engine. Error: `unknown_pair`. If the pair exists but has status `revoked`, error: `pair_revoked`.

3. **Decode and parse canonical payload** -- base64url-decode `X-BPC-Signed-Data` and parse the result as JSON. Error: `invalid_signed_data`.

4. **Timestamp within window** -- verify `|now - payload.timestamp| <= sigWindowMs`. Error: `timestamp_expired`. Records an expired-timestamp counter in the anomaly engine.

5. **Nonce not seen before** -- check the nonce store. If the nonce has been seen, the request is a replay. Error: `replay_detected`. Records a replay counter in the anomaly engine.

6. **Method and path match** -- verify `payload.method === request.method` and `payload.path === request.path`. This prevents signature reuse across different endpoints. Error: `method_path_mismatch`.

7. **Verify ECDSA signature** -- import the pair's registered public key (JWK), canonicalize the payload, and verify the ECDSA-SHA-256 signature. Error: `invalid_signature`.

8. **All checks passed** -- record successful activity on the pair. Return `{ ok: true, pairId, pair }`.

At every failure step, the anomaly engine's denied-request counter is incremented. Specific failure types increment their respective counters (unknown pair probes, signature failures, replay attempts, expired timestamps).

## 9. Canonical Payload

The canonical payload is a flat JSON object with exactly these fields:

| Field | Type | Description |
|-------|------|-------------|
| `body_hash` | string | `"sha256:" + base64url(SHA-256(body)).substring(0, 32)`, or the hash of empty string for bodyless requests |
| `method` | string | HTTP method, uppercase (e.g., `"GET"`, `"POST"`) |
| `nonce` | string | `crypto.randomUUID()` -- unique per request |
| `pair_id` | string | The registered pair ID |
| `path` | string | The request path (e.g., `"/api/data"`) |
| `secret_hmac` | string | `base64url(HMAC-SHA-256(secret, nonce + timestamp)).substring(0, 16)` |
| `timestamp` | number | `Date.now()` -- Unix milliseconds |

**Sorting rule**: keys are sorted in ascending alphabetical order. The object is flat (no nested objects or arrays). The canonical form is `JSON.stringify(sorted_object)`.

This ordering is deterministic: `body_hash`, `method`, `nonce`, `pair_id`, `path`, `secret_hmac`, `timestamp`.

## 10. Anti-Replay Mechanism

BPC prevents replay attacks through two complementary mechanisms:

1. **Nonce uniqueness** -- every request includes a `crypto.randomUUID()` nonce. The server's nonce store tracks all nonces seen within the active window. If a nonce has already been consumed, the request is rejected with `replay_detected`.

2. **Timestamp window** -- every request includes a `Date.now()` timestamp. The server rejects requests where `|server_time - request_timestamp| > sigWindowMs`. Default `sigWindowMs` is 60,000ms (60 seconds).

**Nonce store TTL**: nonces are retained for `2 * sigWindowMs` (default: 120,000ms). This ensures that a nonce cannot be reused even if the original request arrived at the edge of the timestamp window. After the TTL expires, the nonce is evicted from the store.

**Eviction**: the nonce store performs lazy eviction on each lookup, removing entries whose expiry timestamp has passed.

Together, these mechanisms ensure that even a perfectly captured request -- with valid signature, valid HMAC, and correct headers -- cannot be replayed.

## 11. Behavioral Anomaly Detection

The anomaly engine tracks per-box counters:

| Counter | Incremented when |
|---------|-----------------|
| `unknownPairProbes` | A request references a pair ID not in the registry |
| `sigFailures` | ECDSA signature verification fails, or method/path mismatch |
| `replayAttempts` | A nonce has already been consumed |
| `expiredTimestamps` | Timestamp is outside the signing window |
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

The threat score ranges from 0 (no anomalies) to 100 (all requests are attacks). The weights reflect the relative severity: unknown pair probes and signature failures (30% each) are weighted higher than replay attempts and expired timestamps (20% each).

## 12. Step-Up Approval

In `production` mode, sensitive operations require real-time owner approval before the server processes them:

- **Sensitive operations**: HTTP methods `DELETE` and `PUT`, and paths matching `/billing` or `/admin`
- **Approval flow**: the server presents a modal to the box owner with a 30-second countdown. The owner can approve or deny. If the countdown expires, the request is denied.
- **Development mode**: step-up approval is bypassed -- requests proceed without owner intervention.

Step-up approval is an application-layer concern implemented above the BPC verification pipeline. A request must first pass all 8 verification steps before step-up approval is triggered.

## 13. Security Considerations

### What BPC protects against

| Attack | How BPC stops it |
|--------|-----------------|
| Stolen API key (from logs, env vars, source code) | The key alone is useless -- the attacker has no device key to sign requests |
| Wrong device | The ECDSA private key is non-extractable and bound to the generating device's Web Crypto context. Requests from a different device cannot produce valid signatures. |
| Wrong user secret | The secret HMAC is mixed into the canonical payload and covered by the ECDSA signature. Without the correct secret, the HMAC will differ and the signature will not match. |
| Replay attack | Nonce uniqueness + timestamp window. Each nonce can be used exactly once, and the timestamp must be within the signing window. |
| Probing / enumeration | Unknown pair IDs are tracked by the anomaly engine. High probe rates increase the threat score. |
| Supply-chain attack (e.g., malicious npm package) | A stolen API key extracted by malicious code cannot be used from the attacker's device -- no device key, no valid signature. |

### What BPC does NOT protect against

| Attack | Why |
|--------|-----|
| Full browser compromise (TPM-less Web Crypto) | If an attacker has arbitrary code execution in the browser process, they can invoke `crypto.subtle.sign()` with the non-extractable key in-memory. Hardware attestation (WebAuthn) is required for defense against this class of attack and is not included in v0.1.0. |
| Server database breach | If the server's pair registry is compromised, the attacker obtains public keys, secret hashes, and pair metadata. They cannot forge signatures (no private key), but they can learn which pairs exist and potentially attempt offline attacks against weak user secrets. |
| Side-channel attacks | Timing attacks against the ECDSA verification, cache-based side channels, or power analysis are outside the scope of this protocol. Mitigations depend on the underlying Web Crypto and TLS implementations. |
| Compromised server | If the server itself is compromised, the attacker can bypass all verification. BPC is a client-authentication protocol; it does not protect against a malicious server. |

## 14. HTTP Headers

BPC defines three HTTP request headers:

| Header | Type | Description |
|--------|------|-------------|
| `X-BPC-Pair-ID` | string | The registered pair identifier (e.g., `pair_a1b2c3d4e5f6g7h8`) |
| `X-BPC-Signature` | string | base64url-encoded ECDSA-SHA-256 signature over the canonicalized payload |
| `X-BPC-Signed-Data` | string | base64url-encoded UTF-8 of the canonical payload JSON |

All three headers are required on every BPC-authenticated request. Absence of any header results in immediate rejection (`missing_headers`).

## 15. Open Items for v0.2.0

- **HKDF-based server-side HMAC verification** -- derive a verification key from the user secret at pairing time and store it server-side, enabling independent HMAC recomputation without storing the plaintext secret.
- **Persistent pair registry** -- replace the in-memory `Map`-based registry with a durable store (database-backed) that survives server restarts.
- **Multi-instance nonce store** -- replace the in-memory nonce store with a shared store (e.g., Redis) for deployments behind a load balancer.
- **Hardware attestation** -- integrate WebAuthn platform attestation to verify that the device key is backed by a TPM or Secure Enclave, closing the browser-compromise gap.
- **Scope enforcement** -- enforce the pair's `scope` field (`read`, `read-write`, `full`) against the HTTP method and path at verification time.
