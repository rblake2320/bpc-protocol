# Principal Binding HA Design

Status: implemented reference primitives with production deployment gates

## Purpose

BPC treats vendor session IDs as ephemeral child bindings under a persistent
BPC principal. The principal carries authorization continuity, credential
versioning, and audit history across provider sessions, process restarts, key
rotation, and recovery paths.

This document is the normative trace for the principal binding, audit, and
high-availability behavior. Implementation phases should map back to a sentence
in this file.

## Normative Rules

1. A provider session ID is never the identity root. It is an observed child
   binding under a BPC principal.
2. A new provider session must prove possession of the registered principal
   credential with a fresh nonce-bound proof before it is bound.
3. A known principal may receive automatic approval after proof and policy
   validation; it must not bypass proof-of-possession.
4. Session state is not shared across sessions. Authorization context is carried
   by the principal, while each session keeps its own boundary and audit stamp.
5. Fallback replaces the authorization source, not the authorization model.
   Sealed cache and replica paths must enforce the same proof, policy, TTL,
   credential-version, nonce, checkpoint, and tamper checks as the primary.
6. A single global event chain must not be the primary audit structure for the
   mesh. It creates a serialization bottleneck and hides concurrency risks.
7. If a principal can have multiple live sessions, audit events must be
   partitioned by stream, such as `principal_id + provider + agent_instance_id`,
   or represented by an equivalent Merkle/DAG structure.
8. Principal checkpoints must commit the current stream heads for that principal.
9. Optional global checkpoints may commit current principal checkpoint heads for
   system-wide witnessing without serializing every event into one chain.
10. Witness-checkpoint publication frequency and retention period must be
    configurable to meet deployment and compliance requirements.

## Phase Traceability

| Phase | Built behavior | Normative trace |
|---|---|---|
| Phase 1 | Runtime metadata capture | Binding records may include sanitized provider/runtime metadata, but must not include secrets or private keys. |
| Phase 2 | Key-generation capture | Key-generation events may emit fingerprints and metadata; raw private keys, raw secrets, and authorization material must not be emitted. |
| Phase 3 | Principal/session binding | A provider session becomes authorized only after a fresh proof binds it to the persistent BPC principal. |
| Phase 4 | Concurrency-safe audit | Concurrent writers are partitioned into stream chains and committed by principal checkpoints. |
| Phase 5 | Recovery and HA | Replica, sealed-cache, and witness paths preserve the same authorization and audit checks during outages. |

## Binding Record

`SESSION_BOUND` is a first-class audit event. It must include enough information
to prove that an ephemeral provider session became a child binding under a
persistent principal at a specific time.

Minimum fields:

```json
{
  "event_type": "SESSION_BOUND",
  "principal_id": "principal_...",
  "provider": "codex",
  "provider_session_id": "session-...",
  "agent_instance_id": "codex-service-01",
  "policy_digest": "sha256:...",
  "credential_version": 1,
  "bound_at": "2026-06-22T00:00:00Z",
  "runtime_metadata_hash": "sha256:...",
  "proof_digest": "sha256:...",
  "prev_hash": "sha256:...",
  "binding_hash": "sha256:..."
}
```

The proof payload binds the principal credential, provider, provider session ID,
agent instance, policy digest, requested authorization-context hash, supplied
runtime-metadata hash, challenge nonce, and proof timestamp. Effective
authorization comes from a server-side resolver and is empty by default.

## Audit Structure

BPC uses stream chains under each principal, then commits stream heads into a
principal checkpoint.

```text
principal_id
  stream: codex-agent-instance-1 -> linear event chain
  stream: claude-agent-instance-1 -> linear event chain
  stream: gemini-agent-instance-1 -> linear event chain

principal checkpoint:
  commits all current stream heads

optional global checkpoint:
  commits all current principal checkpoint heads
```

This keeps session history queryable by session, by stream, and by principal
without requiring one total order for every concurrent writer.

The design distinction is:

> Hash chaining detects tampering inside the store; external witnessing detects total-store rewrite by the store operator.

## Replication Modes

BPC can run in a single-node development mode, a crash-fault-tolerant replicated
mode, or an enterprise Byzantine-fault-tolerant mode. The claim language is
capability-based: chain state may be replicated through a Byzantine-fault-
tolerant quorum, but a deployment must not claim BFT unless it has enough
independent replicas.

Practical floor:

| Node count | Fault model | Meaning |
|---:|---|---|
| 1 | No HA | Development only; primary loss stops live authorization. |
| 2-3 | CFT | Can tolerate a crash failure if replication and promotion checks pass; does not tolerate a Byzantine node by quorum math. |
| 4+ | BFT | `3f + 1` replicas can tolerate `f` Byzantine replicas when commits require quorum agreement. |

With 3 total nodes, the system has `f = 0` in the BFT sense. It may still be
useful as crash-fault-tolerant replication plus external witnessing. The
external witness closes the integrity gap by making a conflicting chain head
detectable by auditors even when the live quorum is not Byzantine-fault-
tolerant.

Normative BFT wording:

> Chain state may be replicated through a Byzantine-fault-tolerant quorum so that no single chain operator can unilaterally replace accepted history. Periodic external witness checkpoints independently anchor committed chain heads, making even a full-store rewrite detectable by auditors.

The operational distinction is:

> BFT replication prevents a bad operator from becoming truth; external witnessing proves when truth was rewritten anyway.

## External Witness

An external witness records checkpoint hashes outside the control boundary of
the primary chain store. Witnessing can be implemented with a Git commit, remote
append-only log, auditor endpoint, timestamping service, or equivalent external
commitment target.

Witness checkpoints should include:

```json
{
  "checkpoint_id": "global-2026-06-22T18:00:00Z",
  "previous_checkpoint_hash": "sha256:...",
  "principal_heads": {
    "principal_a": "sha256:...",
    "principal_b": "sha256:..."
  },
  "checkpoint_hash": "sha256:...",
  "published_at": "2026-06-22T18:00:03Z",
  "witness": "append-only-log:..."
}
```

Publication policy must be configurable. A local profile may publish every 10
events and retain 90 days of checkpoints. A stricter enterprise profile may
publish every event and retain checkpoints for 7 years or longer. The witness
receiver must not hardcode these values.

Configuration fields should include:

```json
{
  "checkpoint_event_interval": 10,
  "checkpoint_time_interval_ms": 300000,
  "retention_days": 90,
  "witness_target": "append-only-log",
  "audit_lock_on_mismatch": true
}
```

Claim wording:

> The checkpoint publication frequency and retention period are configurable to meet compliance requirements.

## Audit-Lock Recovery Mode

Witness mismatch is not only a detection event. It is a defined system response.

If recomputed chain heads do not match the last accepted external witness, BPC
must enter audit-lock mode:

1. Freeze checkpoint advancement.
2. Reject new principal bindings, key rotations, and authorization-policy
   updates.
3. Preserve the conflicting local chain state as evidence.
4. Allow read-only audit export, verification, and operator reconciliation.
5. Resume writes only after recovery from a verified replica, quorum, backup, or
   explicit administrative reconciliation record.

`AUDIT_LOCK_ENTERED` should be recorded with the observed local head, witnessed
head, principal/global scope, timestamp, and verifier identity.

## Recovery Behavior

| Failure | Recovery layer | Required behavior |
|---|---|---|
| Primary crashes | Hot standby replica | Reads may fail over automatically after health-check failure. Authoritative writes require explicit guard/operator promotion unless a future quorum/lease mode is enabled. |
| Primary and replica unavailable | Local sealed cache | Previously validated principals may operate in bounded degraded mode only while cache TTL, seal, policy, nonce, proof, and checkpoint checks pass. |
| Cache expired or tampered | Fail-closed gate | Deny authorization and require live revalidation or operator recovery. |
| Chain store rewritten | External witness | Detect checkpoint mismatch, freeze checkpoint advancement, enter audit-lock mode. |
| Node store read by attacker | Sealed/encrypted store | Store read access must not grant the principal private key or session-binding authority. |
| Multiple live sessions write concurrently | Stream partitioning or DAG | Keep each writer linear and commit stream heads at principal checkpoints. |

## Remote Replica Secret Handling

Remote replica secret handling has three supported tiers. Tier 3 is the
documented default for the secure remote-replica profile because the unsealing
key remains on the trusted Windows authority and the remote replica cannot
validate independently. Tier 2 is the only tier that provides VPS-side failover
validation, and it is explicit opt-in because it expands the remote trust
boundary. Tier 1 is a metadata-only standby with no secret material on the
remote replica.

| Tier | Remote secret state | Unsealing key location | Remote validation on failover | Defends against |
|---|---|---|---|---|
| 1. Strip | none | n/a | No; metadata standby only | passive and active remote compromise |
| 2. Sealed-at-rest, remote runtime key | ciphertext | remote memory/TPM/HSM at validation time | Yes | passive disk/snapshot compromise, not active memory compromise |
| 3. Sealed, Windows-only key | ciphertext | trusted Windows authority only | No; encrypted backup/restore only | passive and active remote compromise; Windows remains the validator |

Tier 3 shared secrets and validation-capable secret material are envelope-
encrypted before replication. The unsealing key remains resident on the trusted
Windows authority, such as DPAPI, TPM, HSM, or an equivalent local key store. A
remote replica stores ciphertext, metadata, audit records, and checkpoint heads
only. It must not receive plaintext shared secrets, principal private keys,
reusable bearer tokens, or unsealed fallback credentials by default.

Tier 2 remote validation is explicit opt-in through `validateOnFailover` or
`ENABLE_VPS_VALIDATION=true`. In that mode, the deployment may provision
validation-capable material to the remote replica under a hardened operator
policy. That mode must be treated as an intentional security downgrade from
Tier 3 unless it is paired with equivalent key custody, rotation, revocation,
monitoring, and incident-response controls.

Required behavior:

```text
Tier 3 default
  -> remote replica stores ciphertext only
  -> Windows-resident authority holds the unsealing key
  -> remote compromise does not expose validation secrets
  -> remote replica can preserve and witness state, but cannot validate failover

Tier 2 opt-in
  -> validateOnFailover or ENABLE_VPS_VALIDATION=true
  -> remote replica may validate under explicit policy
  -> operator accepts the larger remote trust boundary

Tier 1 metadata standby
  -> no secret material replicated
  -> remote replica stores metadata/checkpoint state only
  -> no failover validation
```

The cryptographic distinction is mandatory:

```text
Windows-only unsealing key -> remote replica cannot validate independently
remote failover validation -> unsealing key or equivalent validator is available remotely
```

## Failover Promotion Model

Reads and writes have different failover rules. Reads may fail over to a replica
automatically after primary health-check failure because they are stale-but-valid
queries against replicated state. Writes are authoritative and can create
split-brain if the primary is only transiently unreachable.

Default Phase 2b policy is guard-gated promotion:

```text
primary healthy
  -> reads and writes use primary

primary health-check failure
  -> reads may use replica
  -> writes remain primary-only

guard/operator promotes replica
  -> promoted replica may accept authoritative writes
  -> promotion record is audit logged

primary returns
  -> client fails back only after state reconciliation
```

Automatic quorum/lease promotion is a future enterprise mode. It must require a
lease, quorum, fencing token, or equivalent single-writer guard before the
replica accepts authoritative writes.

```text
Option A current: guard/operator-gated local promotion
  -> prevents an unpromoted replica from accepting writes
  -> does not fence a still-running primary

Option B future: automatic quorum/lease promotion
  -> faster failover
  -> requires quorum/lease/fencing discipline
```

Required Option A guarantees:

1. `PrimaryUnavailableError` is thrown on writes when the primary is down;
   writes must never silently reroute to a replica.
2. A non-promoted replica returns `503 replica_not_promoted` for authoritative
   client writes, so a buggy or bypassing client still fails closed.
3. The guard promotion command requires `x-guard-token` validation using a
   constant-time comparison; neither the client nor the replica may self-promote.
4. Promotion state is sticky and explicit demotion is required before fail-back;
   it must not auto-clear on a transient primary health probe.
5. The promotion gate is protocol-agnostic and must preserve the same contract
   for BPC and TSK.
6. A global single-writer or split-brain-safety claim additionally requires an
   external lease, quorum, fencing token, or equivalent control that can stop a
   still-running former primary.

Claim wording:

> The local replica gate rejects authoritative writes until it receives an
> authenticated promotion command, and promotion state persists until explicitly
> revoked. This local gate does not itself prove distributed single-writer safety.

## Phase 4 Local Agent Cache

Phase 4 adds a fail-closed local agent cache for bounded offline operation. On
Windows, cached credential material must be sealed with the OS-provided
user-scoped data protection API. The DPAPI scope must be `CurrentUser`, not
`LocalMachine`, so only the same Windows identity that performed the original
binding can unseal the cache. This matches owner-SID-scoped local IPC posture and
prevents other local machine users from decrypting agent cache material.

Minimum sealed cache payload:

```json
{
  "principal_id": "principal_...",
  "provider": "codex",
  "provider_session_id": "session-...",
  "agent_instance_id": "agent-...",
  "binding_hash": "sha256:...",
  "policy_digest": "sha256:...",
  "permissions_hash": "sha256:...",
  "credential_version": 1,
  "checkpoint_hash": "sha256:...",
  "issued_at": "2026-06-22T00:00:00Z",
  "expires_at": "2026-06-22T04:00:00Z"
}
```

The cache verifier must compare the requested policy digest and permissions hash
against the sealed values. When restored BPC state is available, the verifier
must also compare the sealed policy digest against the current principal policy.
A mismatch is treated as cache tampering or stale authorization and fails closed.

Fail-closed behavior must use named errors, not falsy return values:

```text
expired cache -> CacheExpiredError
seal mismatch, flipped binding hash, or policy mismatch -> CacheTamperedError
missing required field -> CacheTamperedError
unsupported DPAPI scope -> CacheTamperedError
```

Required tests:

1. A valid CurrentUser-sealed cache authorizes only while TTL, policy digest,
   permissions hash, checkpoint hash, and binding hash checks pass.
2. An expired cache throws `CacheExpiredError`.
3. A flipped byte in `binding_hash` throws `CacheTamperedError`, not `null`,
   `false`, or a silent degraded state.
4. A policy digest or permissions hash mismatch throws `CacheTamperedError`.
5. A cache sealed with `LocalMachine` scope is rejected for the agent-cache
   profile.

Claim wording:

> Cached credential material is encrypted using the OS-provided user-scoped data protection API, restricting decryption to the identity that performed the original binding, and the sealed cache binds the credential to a principal, binding hash, policy digest, permissions digest, and expiration time before credential material is released.

## Confidentiality Option: Split Storage

Sensitive audit payloads, sealed fallback records, or recovery material may be
stored using XorIDA-style threshold information dispersal so that compromise of
fewer than `k` storage shares does not reveal the protected content, while any
authorized quorum of `k` shares can reconstruct it during recovery.

This protects confidentiality and survivability. Hash chains, checkpoints, and
external witnesses protect integrity. The mechanisms are complementary.

## Implementation Status

Current branch implements the local primitives:

- runtime metadata capture
- key-generation event emission
- fresh proof-of-possession for session binding
- stream chains partitioned by principal/provider/agent instance
- principal checkpoints committing stream heads
- sealed fallback authorization checks that fail closed
- fallback nonce consumption through the server nonce-store abstraction
- DPAPI CurrentUser agent cache that throws named errors on expired, tampered,
  stale-policy, stale-permissions, and missing-cache paths
- authenticated, fresh, monotonic replica envelopes with exact-retry detection
- a local replica promotion gate that fails closed before promotion

Production deployment still needs durable SCM storage, primary/replica
sequence allocation, atomic replica sequence/mutation persistence, global
fencing or lease discipline, promotion orchestration, witness receiver
configuration, audit-lock persistence, and operator reconciliation workflows.
