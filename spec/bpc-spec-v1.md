# BPC Protocol Specification v1.0

## 1. Status and Scope

Bound Pair Credentials (BPC) is a project protocol for authenticating an HTTP
request with a registered public key, a client-held secret, signed request
bindings, freshness, one-use nonces, and closed scopes.

This is not an IETF, W3C, NIST, FedRAMP, or DoD standard. The repository is a
reference implementation under active development. Conformance to this
document does not establish an authorization, certification, hardware identity,
FIPS validation, or regulatory compliance.

The normative implementation for v1.0 is the combination of `@bpc/core`,
`@bpc/client-sdk`, and `@bpc/server`. Python packages implement the same request
format but have different local-key storage properties, described below.

## 2. Terms

- **Pair**: a server-approved record containing a pair ID, public key, closed
  scope, status, and a derived request-HMAC key.
- **Pair key**: an ECDSA P-256 keypair. TypeScript WebCrypto generation marks
  the private key non-extractable through the WebCrypto API. Python serializes a
  software key to PEM. Neither behavior proves hardware or physical-device
  binding.
- **Registration secret**: a client-held value used to derive the request-HMAC
  key. Reference registration helpers require 16-128 characters, upper and
  lower case, a digit, and two special characters.
- **Request-HMAC key**: 32 bytes derived using HKDF-SHA-256 with salt
  `bpc-protocol-hmac-salt-v1` and info `bpc-v1-hmac-key`, encoded as base64url.
  HKDF provides domain separation; it is not a password-hardening KDF.
- **Nonce store**: an atomic first-use store for request UUIDs. Multi-instance
  production deployments require a shared durable backend such as Redis.

## 3. Registration

The reference client performs these steps:

1. Validate the registration secret against the reference project policy.
2. Generate an ECDSA P-256 pair key.
3. Derive the request-HMAC key locally using the HKDF parameters above.
4. Submit `{name, scope, mode, secretHash, pubJwk}` over an authenticated TLS
   channel. `secretHash` is the derived request-HMAC key; despite the historical
   field name, it is not an Argon2 password hash.
5. The server validates the closed scope (`read`, `read-write`, or `admin`),
   mode, name, derived-key encoding, and public-key presence.
6. Production callers use `requestPairing()` followed by an authorized
   `approvePairing()` operation. `registerDirect()` is an internal development
   convenience and must not be exposed as an unauthenticated production route.

The server cannot infer the entropy of a secret from the derived key. Custom
clients must enforce an equivalent registration policy. The derived request key
is sensitive verifier material: a registry compromise reveals the HMAC factor,
although it does not reveal or substitute for the ECDSA private key.

## 4. Canonical Request

Each request carries these headers:

| Header | Meaning |
|---|---|
| `X-BPC-Pair-ID` | Registered pair identifier |
| `X-BPC-Signature` | Base64url ECDSA-SHA-256 signature |
| `X-BPC-Signed-Data` | Base64url canonical JSON payload |
| `X-BPC-Version` | `1.0` |

The canonical payload is a flat JSON object:

```json
{
  "body_hash": "sha256:<full-base64url-sha256>",
  "method": "POST",
  "nonce": "<uuid-v4>",
  "pair_id": "pair_...",
  "path": "/resource",
  "secret_hmac": "<full-base64url-hmac-sha256>",
  "timestamp": 1780000000000,
  "version": "1.0"
}
```

Keys are sorted alphabetically and serialized without extra whitespace. Nested
objects and arrays are rejected. The body hash is the full SHA-256 digest of
the exact transmitted body bytes, prefixed with `sha256:`. A bodyless request
uses the digest of the empty byte string.

The per-request HMAC is:

```text
base64url(HMAC-SHA-256(request-HMAC-key, nonce || decimal(timestamp)))
```

The client signs the complete canonical payload with its pair private key.
ECDSA signatures use the 64-byte IEEE P1363 wire encoding (`r || s`, each
left-padded to 32 bytes) and are then base64url encoded. Python clients convert
their cryptography library's DER output to this WebCrypto-compatible format.

## 5. Verification

An integrating server supplies the exact request method, path, and computed
body hash to `verifyBPCRequest()`. The verifier fails closed unless all relevant
checks pass:

1. Optional IP and pair rate limits.
2. Header presence, length, pair-ID syntax, and protocol header version.
3. Pair existence, active status, expiry, usage cap, and lockout state.
4. Strict canonical-payload parsing and scalar field validation.
5. Request-HMAC verification using the stored derived key.
6. Timestamp freshness within the configured window.
7. Exact method, path, pair ID, and payload-version binding.
8. Closed-scope authorization for both wire and signed methods.
9. Mandatory full body-hash equality.
10. ECDSA signature verification over the canonical payload.
11. Atomic nonce consumption. Nonces are consumed only after the cryptographic
    and request-binding checks pass, preventing an invalid signature from
    burning a captured request's nonce.
12. Ghost/canary pairs return a hard denial after verification and may emit
    shadow/tarpit metadata. Metadata never changes `ok` to true.

Downstream authorization must require `result.ok === true`. A response adapter
may generate decoy content after a hard denial, but it must not grant access to
the protected operation.

## 6. Scope Model

Scopes are a closed enum:

| Scope | Allowed methods |
|---|---|
| `read` | GET, HEAD, OPTIONS |
| `read-write` | GET, HEAD, OPTIONS, POST, PUT, PATCH |
| `admin` | GET, HEAD, OPTIONS, POST, PUT, PATCH, DELETE |

Wildcards and invented scope strings are rejected during registration and
replica ingestion. Application-level resource authorization remains the
integrator's responsibility; BPC method scope is not a complete RBAC or ABAC
system.

## 7. Replay and Freshness

The default signature window is 60 seconds. The server validates a UUID-v4
nonce and timestamp, then atomically consumes the nonce only after signature
verification. A shared Redis nonce backend is implemented for TypeScript.
Process-local memory and file backends do not provide cross-node atomicity.
Python's reference server currently provides a process-local nonce store and
must not be represented as multi-node replay-safe without an external adapter.

## 8. Pair Lifecycle and Rotation

Pair states are `active`, `locked`, `expired`, `rotated`, and `revoked`.
Rotation is authorized by the old pair's private key and binds the old pair ID,
new public JWK, purpose, and timestamp. The implementation disables the old pair
before persisting the new pair. A persistence failure therefore fails closed and
requires operator recovery; it does not leave both credentials active.

Rotation does not currently prove hardware custody, provide automatic client
secret replacement, or establish a distributed credential-lifecycle service.

## 9. Audit Evidence

The TypeScript audit API provides hash-chained entries with monotonic sequence,
previous hash, and entry hash. Interior modification and broken retained links
are detected by `verifyChain()`. Tail truncation is detectable only when the
verifier supplies a trusted external head. The entries are not cryptographically
signed by this repository, so the audit layer is tamper-evident but does not by
itself establish signer attribution or non-repudiation.

`MemoryAuditLog` is development/process-local. `PgAuditLog` adds durable schema
controls, but deployment permissions, backups, external anchoring, retention,
and independent assessment remain operator responsibilities.

## 10. Replication and Promotion

The TypeScript HA path sends a canonical `bpc.replica.v1` envelope containing a
stable source ID, monotonic sequence, fresh timestamp, and complete mutation.
HMAC-SHA-256 authenticates and integrity-protects the envelope. The receiver
rejects expired, malformed, stale, gapped, and same-sequence conflicting
operations. Only an exact operation retry is idempotent.

The included sequence source and apply guard are process-local development
implementations. Production HA requires:

- a durable monotonic sequence allocator;
- atomic persistence of the accepted sequence, operation digest, and mutation;
- snapshot reconciliation after any queue shed or sequence gap;
- authenticated transport and key rotation;
- promotion eligibility checks against replica convergence;
- an external lease, quorum, fencing mechanism, or equivalent single-writer
  control when automatic split-brain resistance is required.

`PromotionController` is a local guard-command gate for a replica. It does not
fence a still-running primary and must not be cited alone as proof of a global
single-writer invariant.

## 11. Principal Session Binding

The in-memory reference ledger binds a provider session to a persistent
principal only after fresh proof of possession. The signed proof covers provider,
session, agent instance, policy digest, requested authorization-context hash,
runtime-metadata hash, nonce, and timestamp. Authorization is supplied by a
server-side resolver; caller-requested roles are not granted by default. Proof
nonces are one-use.

Fallback authorization verifies a sealed cache, TTL, policy and checkpoint
bindings, fresh proof, and an atomic nonce store. Production use requires durable
principal/checkpoint storage and a durable nonce backend. The in-memory ledger
is executable reference behavior, not a production persistence claim.

## 12. Local Key Storage

- TypeScript WebCrypto keys are non-extractable through the WebCrypto export
  API, subject to the runtime's security boundary.
- The Python client serializes a private key and registration secret in its
  local pair file. That reference storage is not suitable for production secret
  custody without OS- or HSM-backed protection and file access controls.
- No code in this repository demonstrates TPM attestation, Secure Enclave
  attestation, or hardware-bound key provenance.

## 13. Security Boundaries

BPC narrowly establishes that a request passed the implemented checks using the
registered verifier material at verification time. It does not protect against:

- compromise of the client process that can invoke the private key and read the
  registration secret;
- a malicious verifier or application that bypasses `verifyBPCRequest()`;
- insecure TLS termination or incorrect method/path/body-hash integration;
- denial of service beyond the configured rate-limit and tarpit behavior;
- database, log, backup, or key-management failures outside configured stores;
- authorization decisions beyond the closed HTTP-method scope;
- certification, accreditation, legal admissibility, or compliance status.

Claims about replay resistance require the actual nonce backend and deployment
topology to be identified. Claims about audit truncation detection require the
actual external anchor. Claims about HA require durable sequencing, convergence,
and fencing evidence from the deployed system.

## 14. Conformance Evidence

The repository's tests cover canonicalization, request binding, signature and
HMAC failure, nonce replay and nonce-burn resistance, scope confusion, lifecycle
states, audit-chain tampering, HA envelope authentication and ordering,
principal proof binding, and Python/TypeScript request-format behavior.

Test counts are commit-specific. A release claim must cite the commit, command,
environment, and output rather than copying a permanent count into this spec.

## 15. Future Extensions

Hardware-backed WebAuthn attestation, distributed fencing, durable replica apply
guards, signed external audit receipts, and protected Python key custody are
possible extensions. They are not implemented merely because the underlying
platform exposes related primitives.
