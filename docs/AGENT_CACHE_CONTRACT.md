# Agent Cache Contract

Status: normative behavioral contract for agent credential cache implementations

## Purpose

The agent credential cache is a patent-linked fail-closed recovery primitive. It
allows a previously bound agent to restore bounded authorization from a locally
sealed cache when the live authority is unavailable, without turning outage
handling into an authorization bypass.

This contract applies to every implementation of the cache, including the
TypeScript `agent-cache.ts` implementation and any Python
`agent_credential_cache.py` implementation. Implementations may differ in
storage APIs and platform bindings, but they must satisfy the same behavioral
vectors.

## Normative Rules

1. The cache is an offline authorization source for a previously validated
   principal, not a fallback password and not a trust bypass.
2. Cached credential material must be encrypted or sealed using user-scoped
   operating system protection. On Windows, DPAPI scope must be `CurrentUser`,
   never `LocalMachine`, for the agent-cache profile.
3. The sealed payload must bind authorization policy to the credential binding.
   A cache that stores the credential without policy context is non-conforming.
4. The verifier must fail closed using named errors. It must not return `null`,
   `false`, `undefined`, or silently degrade on expired, tampered, stale-policy,
   or invalid-scope cache records.
5. A valid cache authorizes only while TTL, principal, binding, policy,
   permissions, credential version, and checkpoint expectations match.
6. Logical conformance tests may use deterministic test protectors, but each
   platform implementation must also have a real OS-protection smoke test where
   the platform API is available.

## Required Payload Fields

Minimum sealed payload:

```json
{
  "version": "1",
  "principal_id": "principal_...",
  "provider": "codex",
  "provider_session_id": "session-...",
  "agent_instance_id": "agent-...",
  "binding_hash": "sha256:...",
  "policy_digest": "sha256:...",
  "permissions_hash": "sha256:...",
  "credential_version": 1,
  "checkpoint_hash": "sha256:...",
  "issued_at": 1782150000000,
  "expires_at": 1782153600000,
  "credential_material": {}
}
```

Implementations may add fields, but they must not omit the required fields when
those values are known to the caller. Unknown optional identity fields should be
represented explicitly by the caller's schema rather than silently removed by
the cache implementation.

## Required Error Semantics

| Condition | Required behavior |
|---|---|
| Missing cache entry | `CacheMissError` or implementation-equivalent named miss error |
| Expired cache | `CacheExpiredError` |
| Corrupted sealed blob / ciphertext | `CacheTamperedError` |
| `binding_hash` mismatch | `CacheTamperedError` |
| `policy_digest` mismatch | `CacheTamperedError` |
| `permissions_hash` mismatch | `CacheTamperedError` |
| `checkpoint_hash` mismatch | `CacheTamperedError` |
| `credential_version` mismatch | `CacheTamperedError` |
| Missing required field | `CacheTamperedError` |
| Unsupported machine/global scope | `CacheTamperedError` or implementation-equivalent named invalid-scope error |

Implementations may expose language-native subclasses or error codes, but the
calling code must be able to distinguish miss, expired, and tampered/invalid
states explicitly.

## Required Conformance Vectors

Each implementation must load equivalent conformance vectors. A shared vector
file may be added later, but the required cases are:

1. `valid_current_user_cache`
   - payload has matching `principal_id`, `binding_hash`, `policy_digest`,
     `permissions_hash`, `credential_version`, `checkpoint_hash`, and unexpired
     `expires_at`
   - expected result: cache opens successfully
2. `expired_cache`
   - same payload, but `expires_at <= now`
   - expected result: `CacheExpiredError`
3. `blob_tamper`
   - flip one byte in the sealed ciphertext/blob
   - for Windows DPAPI, flip a byte in the ciphertext/MAC region, such as the
     middle or tail of the protected blob; do not use the leading
     provider/version header as the only tamper target because those bytes may
     not be authenticated by DPAPI
   - expected result: `CacheTamperedError`
4. `binding_hash_tamper`
   - sealed payload contains a different `binding_hash`
   - expected result: `CacheTamperedError`
5. `stale_policy_digest`
   - expected policy differs from sealed `policy_digest`
   - expected result: `CacheTamperedError`
6. `stale_permissions_hash`
   - expected permissions hash differs from sealed `permissions_hash`
   - expected result: `CacheTamperedError`
7. `checkpoint_mismatch`
   - expected checkpoint differs from sealed `checkpoint_hash`
   - expected result: `CacheTamperedError`
8. `credential_version_mismatch`
   - expected credential version differs from sealed `credential_version`
   - expected result: `CacheTamperedError`
9. `missing_required_field`
   - remove one required field from the sealed payload before sealing
   - expected result: `CacheTamperedError`
10. `unsupported_scope`
    - cache envelope claims `LocalMachine`, machine scope, or equivalent
    - expected result: named fail-closed invalid-scope/tamper error

## Real Platform Smoke Tests

Windows implementations must include a real DPAPI smoke test, separate from
deterministic logical vectors:

1. Seal a valid payload using `CurrentUser`.
2. Unseal the payload using the same Windows identity.
3. Flip one byte in the sealed ciphertext/MAC region. For Windows DPAPI, choose
   a middle or tail byte and do not rely on the leading provider/version header
   as the tamper target.
4. Verify unseal fails with `CacheTamperedError` or the implementation-equivalent
   named tamper error.

The smoke test must not use a mock/fake DPAPI provider. If the platform is not
Windows or DPAPI is unavailable, the test may be skipped with an explicit reason;
it must not silently pass.

## Python Module Docstring

Python implementations should include this reference in the module docstring:

```python
"""Fail-closed agent credential cache.

This module implements the behavioral contract in
docs/AGENT_CACHE_CONTRACT.md. Any change to cache payload fields, DPAPI scope,
or fail-closed error semantics must keep the TypeScript and Python
implementations conformant with that shared contract.
"""
```

## Patent Claim Language

> Cached credential material is encrypted using the OS-provided user-scoped data protection API, restricting decryption to the identity that performed the original binding, and the cache verifier fails closed with named errors when policy, permissions, binding, credential version, checkpoint, TTL, or tamper checks fail.
