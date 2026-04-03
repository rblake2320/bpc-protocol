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

## Status

v0.1.0 -- Working reference implementation. Patent pending. Not yet production-hardened.

The `non-extractable` flag on device keys prevents JavaScript-level key extraction. For hardware-level binding (TPM/Secure Enclave), platform attestation via WebAuthn is required and is planned for v0.2.0. See `spec/bpc-spec-v1.md` for the full protocol specification.

## Open Items (v0.2.0)

- HKDF-based server-side HMAC verification (independent secret validation without storing plaintext)
- Persistent pair registry (database-backed, survives restarts)
- Multi-instance nonce store (Redis-backed for load-balanced deployments)
- Hardware attestation via WebAuthn (TPM/Secure Enclave key binding)
- Scope enforcement at verification time (read / read-write / full)

## Attribution

Conceived and designed by R. Blake.
