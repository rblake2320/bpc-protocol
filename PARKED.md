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
- **Reason:** atomic `SET NX PX` proves concurrent first-use ordering while the
  keys exist. Redis persistence and replication can have deployment-specific
  loss windows, and the package cannot detect arbitrary deletion.
- **Current claim:** named Redis errors fail closed; deployments must use
  `noeviction` and quarantine authorization for the full retention horizon
  after any failover whose nonce durability is uncertain.
- **Restore only with:** a deployment-specific durable topology, measured loss
  bounds, restart/failover evidence, deletion detection or trusted checkpoints,
  and adversarial recovery tests.
