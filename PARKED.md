# Parked Claims And Designs

This file preserves removed or rejected material without leaving it active in
product or security claims. Git history contains the original wording.

## P-001: Hardware-bound device identity

- **Parked:** `extractable: false` described as hardware or TPM device binding.
- **Reason:** WebCrypto non-exportability blocks ordinary JavaScript export but
  does not prove hardware custody or device attestation.
- **Current claim:** BPC proves possession of an authorized pair signing key.
- **Restore only with:** implemented attestation, verified certificate chain,
  device-policy binding, revocation, and named runtime evidence.

## P-002: DoD IL4-IL7 hardening or compliance

- **Parked:** product-level DoD Impact Level and `IL7` wording.
- **Reason:** impact levels apply to authorized cloud service offerings; there
  is no current DoD CC SRG IL7. Tests do not create an authorization.
- **Current claim:** narrowly scoped controls may support an assessed system.

## P-003: FIPS-validated implementation

- **Parked:** calling algorithms or the Node/WebCrypto runtime FIPS validated.
- **Reason:** algorithm selection is not CMVP module validation. The exact
  module, version, mode, and operating environment must be validated.

## P-004: Wildcard credential scopes

- **Parked:** `read:*` and other glob/prefix semantics in BPC credentials.
- **Reason:** ambiguous matching increases privilege-escalation risk.
- **Current design:** closed coarse scopes plus application policy.

## P-005: Global split-brain-safe promotion

- **Parked:** describing the local `PromotionController` as a distributed
  single-writer guarantee.
- **Reason:** it prevents an unpromoted replica from writing but cannot fence a
  still-running primary during a partition.
- **Restore only with:** durable lease/quorum/fencing, store-boundary
  enforcement, replica-currency checks, restart recovery, and adversarial
  partition evidence from the deployed topology.

## P-006: Production-complete HA replication

- **Parked:** treating the in-memory sequence source, apply guard, and retry
  queue as a production HA system.
- **Reason:** production still needs durable monotonic allocation, atomic
  sequence/digest/mutation persistence, queue durability, snapshot
  reconciliation, and promotion eligibility after gaps.
- **Current claim:** authenticated, fresh, ordered envelope behavior is
  implemented and exercised with development adapters.

## P-007: Protected Python credential custody

- **Parked:** describing the Python client's PEM and secret file as a hardened
  credential store.
- **Reason:** owner-only file permissions and atomic replacement do not equal
  DPAPI, TPM, HSM, keyring, or remote-attested custody.
- **Restore only with:** implemented protected storage, migration/rotation,
  recovery, compromise tests, and deployment evidence.

## P-008: Signed, externally anchored audit attribution

- **Parked:** non-repudiation, signer attribution, and truncation resistance
  without a trusted external head.
- **Reason:** the repository audit entries are hash-chained but not signed or
  automatically anchored outside the host.
- **Restore only with:** provisioned signing identity, verification tooling,
  external/WORM anchoring, deletion/truncation tests, and custody procedures.

## P-009: Multi-node Python replay resistance

- **Parked:** applying the TypeScript Redis replay result to the Python server.
- **Reason:** the Python package currently supplies a process-local nonce
  store. Cross-node atomicity is not implemented there.
- **Restore only with:** a shared atomic Python backend and a two-process live
  integration test.

## P-010: Lossless Redis replay continuity across failover

- **Parked:** claiming that the TypeScript Redis nonce backend alone preserves
  replay evidence through every restart, failover, eviction, or data-loss event.
- **Reason:** the governed Lua operation proves expected-epoch validation and
  concurrent first-use ordering on the Redis instance that executes it. Redis
  persistence and asynchronous replication can still have deployment-specific
  loss windows. A restored internally consistent snapshot with the same epoch,
  privileged selective nonce deletion, or policy drift between CONFIG checks
  is not detected by that operation. One client's CONFIG response also does
  not attest the configuration of every Redis Cluster member.
- **Current claim:** the awaited TypeScript governed factory verifies live
  `noeviction`, binds one namespace horizon, shares an epoch/quarantine across
  verifiers, denies a missing marker or an epoch change relative to the running
  process/trusted checkpoint, and atomically combines those checks with nonce
  consumption. Uncertain state and Redis failures produce named fail-closed
  results. A cold process without a trusted expected epoch can adopt any
  existing epoch and cannot attest that snapshot's freshness.
- **Restore only with:** a deployment-specific durable topology, measured loss
  bounds, restart/failover evidence, deletion detection or trusted checkpoints,
  immutable/monitored policy, and adversarial recovery tests.

## P-011: Ungoverned Redis helper as production composition

- **Parked:** describing `createRedisBackedNonceStore()` or raw `SET NX PX` as
  sufficient production replay continuity.
- **Reason:** the helper has no shared epoch, no quarantine, and no atomic
  continuity comparison. State loss can make an already-used nonce look fresh.
- **Current claim:** it is an isolated test/development primitive and requires
  `continuityMode: 'ungoverned-development'`. Production TypeScript consumers
  use the awaited governed factory.
- **Restore only with:** not applicable; use the governed composition rather
  than weakening its boundary.

## P-012: Live wall-clock TTL as an exact unit-test boundary

- **Parked:** reading a countdown from the host clock and requiring it to remain
  at least 1000ms after awaited work.
- **Reason:** one millisecond of legitimate scheduling produced a false failure
  without identifying a shorter configured quarantine.
- **Current design:** freeze the fake model's clock and assert the exact 1000ms
  horizon, with restoration protected even if asynchronous cleanup fails; live
  Redis tests remain responsible for real countdown behavior.
- **Restore only with:** a deterministic clock supplied by the test harness that
  preserves the same exact semantic assertion.

## P-013: Durable-outbox mechanism as high-availability proof

- **Parked:** describing the PostgreSQL durable-outbox mechanism or its
  single-node integration as production HA, lossless replication, or measured
  failover capability.
- **Reason:** one PostgreSQL service cannot establish behavior during two-node
  database/Redis failover, split brain, or network partition.
- **Current claim:** a production PostgreSQL transactor and single-node durable
  outbox mechanism exist and are tested against real PostgreSQL.
- **Restore only with:** issue #16's real two-node PostgreSQL and Redis drill,
  adversarial stale-writer/split-brain cases, and recorded RPO/RTO evidence.
