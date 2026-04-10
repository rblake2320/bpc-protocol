# BPC -- Bound Pair Credentials

> API Keys are broken. We built something better.

A request authentication protocol where every API call is device-signed, pair-verified, secret-locked, and replay-proof.

## What It Is

Static API keys are a single string that grants full access to whoever holds it. They get committed to repos, leaked in logs, stolen by supply-chain attacks, and replayed indefinitely. Once an API key is compromised, the attacker has the same access as the legitimate client -- and you may never know.

BPC replaces static keys with a multi-factor, per-request signing protocol. Each client generates a device-bound ECDSA keypair (non-extractable via Web Crypto API), registers it with the server through an explicit pairing process, and signs every request using the private key, a user-chosen secret, a fresh nonce, and a timestamp. A stolen credential is useless without the device key, the secret, and a fresh nonce window -- all at the same time.

## The 5 Layers

| Layer | What it does | What it stops |
|-------|-------------|---------------|
| Device-Bound Keys | ECDSA P-256 keypair generated with `extractable: false` via Web Crypto API | Stolen key used from another device -- no private key, no valid signature |
| Explicit Pair Registry | Every client must be individually registered and approved before making requests | Unknown callers, enumeration, unauthorized access |
| User-Chosen Secret | A secret mixed into every signature via HMAC derivation -- never stored or transmitted in plaintext | Stolen key + stolen device -- attacker still lacks the secret |
| Anti-Replay Protection | Unique nonce + 60-second timestamp window on every request | Captured requests replayed later -- nonce already consumed, timestamp expired |
| Behavioral Anomaly Engine | Tracks unknown pair probes, signature failures, replay attempts, expired timestamps | Probing, brute-force, coordinated attack patterns |

## Quick Start

```bash
cd examples/full-stack
npm install && npm start
```

This starts a BPC-protected Express server and a client that registers, pairs, and makes signed requests.

## Installation

```bash
npm install @bpc/server        # server verification middleware
npm install @bpc/client-sdk    # client signing SDK
```

Both packages depend on `@bpc/core` (installed automatically).

## Server Usage

```typescript
import express from 'express';
import { PairRegistry, ServerNonceStore, AnomalyEngine, verifyBPCRequest } from '@bpc/server';

const app = express();
const registry = new PairRegistry();
const nonceStore = new ServerNonceStore();
const anomaly = new AnomalyEngine();

app.use(async (req, res, next) => {
  const result = await verifyBPCRequest({
    pairId: req.headers['x-bpc-pair-id'] as string,
    signature: req.headers['x-bpc-signature'] as string,
    signedData: req.headers['x-bpc-signed-data'] as string,
    method: req.method,
    path: req.path,
  }, registry, nonceStore, anomaly);

  if (!result.ok) return res.status(401).json({ error: result.error });
  next();
});
```

## Client Usage

```typescript
import { BPCClient } from '@bpc/client-sdk';
import { generateKeypair, hashSecret } from '@bpc/core';

// After pairing (see spec for full flow):
const client = new BPCClient({
  serverUrl: 'https://api.example.com',
  pairId: 'pair_a1b2c3d4e5f6g7h8',
  keypair: myKeypair,
  secret: 'mySecret',
});

const response = await client.fetch('/api/data');
```

## Architecture

```
packages/
  core/          Crypto primitives, canonical payload, nonce generation, HMAC
  server/        Pair registry, nonce store, anomaly engine, verification pipeline
  client-sdk/    BPCClient with automatic request signing and fetch wrapper
```

- **`@bpc/core`** -- shared cryptographic functions (ECDSA key generation, signing, verification, HMAC derivation, canonicalization). Framework-agnostic, works in browsers and Node.js.
- **`@bpc/server`** -- the verification pipeline (`verifyBPCRequest`), pair registry, server-side nonce store, and behavioral anomaly engine. Framework-agnostic -- bring your own HTTP framework.
- **`@bpc/client-sdk`** -- `BPCClient` class that handles request signing and header construction. Provides a `fetch()` wrapper that automatically attaches BPC headers.

## Security Properties

The following properties are enforced by the protocol and verified by the test suite. Claims are scoped to **correctly implemented, correctly deployed, correctly operated** systems.

| Property | Claim | How it holds |
|----------|-------|--------------|
| Credential isolation | A stolen API key cannot be used from a different device | ECDSA private key generated with `extractable: false` — cannot be exported by JavaScript or extracted by a compromised application layer |
| Secret binding | A stolen device cannot be used without the user secret | Every request carries an HMAC derived from `hashSecret(secret)` mixed into the signed payload. The server verifies this independently of the ECDSA signature. |
| Replay resistance | A captured valid request cannot be replayed | Per-request cryptographic nonce (consumed on first use) + 60-second timestamp window. Both must be valid simultaneously. |
| Body integrity | A valid signature cannot be transplanted onto a different request body | `body_hash` (SHA-256 of the raw request body) is included in the signed canonical payload. Servers compute the hash of the received body and compare. |
| Rotation authenticity | A key rotation cannot be initiated by an attacker who holds only the pair ID | The rotation payload (`old_pair_id`, `new_pub_jwk`, `timestamp`, `purpose`) is signed by the existing device private key. Server validates the signature and all bound fields before accepting the new key. |
| Behavioral detection | Repeated probing, failed signatures, and replay attempts are tracked | Anomaly engine records per-pair threat scores. Operators can gate on score thresholds. |

**What BPC does not claim:**

- Protection against a fully compromised host (OS-level key extraction or secret theft are outside protocol scope)
- Hardware attestation — the `extractable: false` flag prevents JS-layer extraction; TPM/Secure Enclave binding requires WebAuthn attestation (planned v0.2.0)
- Quantum resistance — ECDSA P-256 is vulnerable to Shor's algorithm once cryptographically relevant quantum computers exist. NIST deprecates P-256 by 2030. Migration path to ML-DSA (CRYSTALS-Dilithium, FIPS 204) is planned before that deadline.

## Status

v1.0.0 — Production-hardened reference implementation. Patent pending.

Three independent adversarial test passes were run against the codebase, finding and resolving: secret HMAC enforcement gap, rotation payload field binding, body hash enforcement in the example server, HMAC comparison timing, and Math.random() in the Redis rate limiter. All 57 tests (core, server, client-sdk) pass.

The `non-extractable` flag on device keys prevents JavaScript-level key extraction. For hardware-level binding (TPM/Secure Enclave), platform attestation via WebAuthn is required and is planned for v0.2.0. See `spec/bpc-spec-v1.md` for the full protocol specification.

## Roadmap (v0.2.0)

- Persistent pair registry (database-backed, survives restarts)
- Multi-instance nonce store (Redis-backed for load-balanced deployments)
- Hardware attestation via WebAuthn (TPM/Secure Enclave key binding)
- ML-DSA migration path (post-quantum, pre-2030 NIST deadline)

## Attribution

Conceived and designed by R. Blake.
