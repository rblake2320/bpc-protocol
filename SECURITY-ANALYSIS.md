# BPC Security Analysis

This document describes the security boundary implemented by this repository.
It is not a certification, compliance determination, production authorization,
or proof that every attack is infeasible.

## Implemented Request Checks

The TypeScript verifier checks a registered pair's status and coarse scope,
validates request structure and freshness, verifies a secret-derived HMAC and an
ECDSA P-256 signature over the canonical request, and atomically consumes a
nonce after the remaining checks pass. Method, path, pair ID, protocol version,
and body hash are bound to the signed payload.

Distributed verifiers require a shared atomic nonce backend. The repository
contains a Redis adapter and a live-Redis integration test. The in-memory
backend is for development and single-process tests.

## HA Boundary

Replica mutations use HMAC-authenticated envelopes containing a stable source
identifier, a monotonic sequence, a fresh timestamp, and a validated
operation. The receiver rejects stale, duplicate-changing, out-of-order,
expired, or modified envelopes. A production receiver must persist its accepted
sequence and operation digest atomically with the replicated mutation, and the
source sequence allocator must be durable; the included memory implementations
are test/development adapters.

Promotion remains an operational control. A deployment must fence the previous
writer, confirm replica currency, protect guard credentials, and audit promotion
and demotion. Code-level routing alone is not proof that a distributed system
cannot enter split brain.

## Principal Session Boundary

Session proofs bind provider/session identifiers, policy digest, requested
authorization context, runtime metadata, freshness, and a one-use challenge.
Requested authorization is not automatically granted: a server-side resolver
must return the effective context. The default in-memory ledger grants no
caller-requested authorization.

The in-memory ledger is hash-chained but not externally signed or anchored.
Hash chaining detects retained-entry modification when verification state is
intact; it does not by itself prevent complete deletion or coordinated rewriting
by an attacker controlling the host.

## Key And Identity Boundary

WebCrypto can create an ECDSA private key with `extractable: false`. That blocks
ordinary export through the WebCrypto API. It does not prove TPM storage,
hardware attestation, physical-device identity, or resistance to a compromised
browser/host that can invoke the key.

The Python client currently persists its software private key and secret for
client reuse. Deployments must supply operating-system protected storage and
appropriate access controls before treating that client as a high-assurance
credential holder.

## Explicit Non-Claims

BPC does not independently provide:

- TLS or confidentiality;
- hardware-backed identity or remote attestation;
- application resource authorization beyond the closed HTTP-method scope;
- protection after compromise of all credential factors or the verifier host;
- FIPS 140 validation of the deployed module;
- FedRAMP, DoD Impact Level, HIPAA, PCI DSS, SOC 2, ISO 27001, or other
  compliance/authorization status;
- post-quantum security.

Candidate control mappings in other documents require review against the exact
deployment boundary by a qualified assessor.

## Required Adversarial Coverage

Release validation should include invalid-signature nonce burning, cross-node
nonce replay, stale replica resurrection, envelope tampering, sequence gaps,
session-proof replay, unsigned authorization changes, scope confusion, key
rotation, restart recovery, and promotion/fencing failure. A passing named test
establishes only its stated proposition.
