# Change Log

## 2026-07-16

- Enterprise Actions run `29476950456` exposed two evidence defects: the
  heterogeneous-horizon unit test measured a live countdown and intermittently
  saw 999ms instead of the just-established 1000ms horizon, and the root npm
  workspace runner continued into later workspace output after that failure.
  The test now freezes `Date.now()`, restores it in a cleanup-safe nested
  `finally`, and asserts the exact 1000ms property. A tested sequential runner
  forwards root arguments to every workspace and stops at the first nonzero
  result. This improves test determinism, argument propagation, failure
  locality, and log clarity; it does not change production continuity logic or
  imply that npm's former workspace runner returned success on failure.
- Corrected PR #14 after independent review found that its continuity check was
  a non-atomic local preflight, bootstrap returned before a first reconcile,
  CONFIG parsing accepted ambiguous shapes, and the interval loop could
  overlap or outlive shutdown.
- Added the awaited `createGovernedRedisBackedNonceStore()` production factory.
  It requires exact live `maxmemory-policy noeviction`, bootstraps a shared
  horizon configuration, epoch, and quarantine, places all governed keys in
  one Redis Cluster hash slot, and checks the config/expected epoch/quarantine
  in the same Lua EVAL that consumes the nonce. A heterogeneous verifier cannot
  join the namespace or shorten its quarantine.
- A fresh or missing continuity namespace now quarantines every verifier for
  the full derived replay horizon plus allowance. Epoch change, malformed
  shared state, timeout, disconnect, unknown response, and reconcile failure
  deny without memory fallback. `authorization_quarantined` and
  `replay_store_unavailable` are distinct named 503 results.
- Replaced the overlapping interval with a serialized self-scheduling wrapper.
  The cadence must be shorter than nonce retention; observer failures are
  contained; asynchronous idempotent shutdown closes authorization first and
  drains the active wrapper. An ioredis command that already timed out cannot be
  cancelled by JavaScript and may settle later; this boundary is documented and
  a regression proves a late nonce write cannot authorize the denied caller.
- Kept `createRedisBackedNonceStore()` only as an explicitly acknowledged
  `ungoverned-development` helper so existing test adapters remain available
  without being mistaken for production continuity evidence.
- Added stateful adversarial unit coverage and expanded the actual Redis runner.
  Local evidence: 249/249 Node workspace tests, 81/81 Python tests, 22/22 live
  governed Redis assertions, 28/28 live HTTP adversarial assertions, build,
  cross-language interop, npm package dry-runs, and production dependency audit
  all passed. PostgreSQL was not listening locally. GitHub Actions then passed
  both Node gates (including the real PostgreSQL integration) and both Python
  gates for implementation commit `2b3ebf5` in runs `29475725228` and
  `29475727870`.
- Preserved the bounded claim: one Redis EVAL closes the preflight/consume
  interleaving on the executing instance. It does not prove same-epoch snapshot
  freshness, uncheckpointed cold-restore identity, asynchronous replication
  durability, prevention of privileged selective deletion, cancellable Redis
  commands, or immutable runtime Redis policy.

## 2026-07-15

- Corrected PR #8 beyond its two stale assertions: copied all authorization
  inputs away from the live pair before later awaits, froze the public snapshot
  before nonce-store activity, and added a deterministic concurrent scope
  mutation regression. The snapshot retains the scope used by verification
  while the registry independently changes.
- Migrated demo and full-stack consumers from `result.pair.scope` to
  `result.snapshot.scope`. The required adversarial runner exposed this real
  composition dependency when the admin scenario failed after the mutable pair
  was removed.
- Removed the `/health` verifier shortcut that returned `ok: true` without BPC
  credentials. A regression now requires missing credentials on that path to
  fail with `missing_headers`; service health must be routed outside the
  authorization verifier.
- Reopened issue #2 after design review showed the atomic Redis primitive was
  present but the claimed standalone verifier composition was incomplete.
- Added a validated TypeScript Redis nonce builder with explicit deployment
  namespaces, retention derived from the signature window, bounded command
  latency, injected standalone-server wiring, and named fail-closed 503 denial
  without memory fallback.
- Replaced the direct-store Redis runner with built-package verification through
  two independent BPC verifiers. Final focused evidence: 142/142 server tests;
  188/188 Node workspace tests; 8/8 live Redis assertions including 64 signed
  concurrent uses, disconnect, TTL, namespace isolation, and real noeviction
  OOM; 28/28 live HTTP adversarial assertions; 81/81 Python tests; PostgreSQL,
  cross-language, package, build, and dependency-audit gates passed.
- Redis data-loss continuity remains explicitly parked: deployments must use
  noeviction and quarantine after a failover whose nonce history is uncertain.

- Re-audited closed issue #1 and found the TypeScript implementation rejected
  wildcard scopes while the shipped Python registry still accepted arbitrary
  strings. Request verification later denied those strings, but the documented
  registration-time guarantee was not true across both implementations.
- Added Python construction, registry, client-intake, and corrupt-store scope
  validation. Python verification now reports `invalid_scope` before payload
  cryptography for malformed stored authority. Focused Python suites pass
  81/81 (44 client, 37 server), and Ruff is clean on the changed surface.

- Post-merge validation found that the two standalone HTTP adversarial runners
  were not part of CI. Both used a secret rejected by the current policy, and
  the scope runner still called SDK methods removed during hardening.
- Repaired both runners against the current SDK, replaced static/skip results
  with live registration and anomaly-evidence assertions, and added an
  isolated loopback test-server orchestrator to the required CI matrix.
- Local correction verification passed 171 Node tests, 71 Python tests, 28
  live HTTP adversarial assertions, cross-language interoperability, npm
  package dry-runs, full and production dependency audits, a 64-way two-client
  Redis replay race, and PostgreSQL migration/reconnect durability.

- Audited open issues, draft PR state, package builds, Node tests, Python tests,
  dependency audit, and protocol claims.
- Added a non-mocked Redis nonce integration test and CI service contract.
- Documented the closed scope model and parked wildcard matching.
- Removed unsupported hardware-binding, IL7, and FIPS-validation claims from
  active product and security descriptions; preserved restoration conditions in
  `PARKED.md`.
- Replaced the adversarial runner's unsupported `PRODUCTION READY` conclusion
  with a result scoped to the named scenarios executed in that run.
- Upgraded the Node test runner and generated a root workspace lock. `npm audit`
  reports zero known vulnerabilities in the resolved dependency graph.
- Added named registration/update assertions proving wildcard and namespaced
  credential scopes are rejected.
- Corrected the Python/TypeScript wire contract: P1363 ECDSA signatures, matching
  HKDF parameters, full body hashes, and canonical JWK fingerprints now pass in
  both directions through a real cross-language integration command.
- Bound principal-session proofs to authorization and runtime metadata, made
  proof and fallback nonces one-use, and made effective authority server-owned.
- Added authenticated, source-bound, ordered replication envelopes and
  fail-closed receiver checks for tampering, expiry, gaps, stale operations, and
  same-sequence conflicts. Durable HA state and global fencing remain parked.
- Moved verifier nonce consumption after cryptographic and request-binding
  checks, made body hash and pair/version binding mandatory, and changed shadow
  and ghost outcomes to hard denials.
- Corrected Python registration, rotation, revocation, credential-file failure,
  and request-HMAC behavior. The Python credential file is still not protected
  by DPAPI, TPM, HSM, or an operating-system keyring.
- Made TypeScript request signing hash the exact transmitted bytes and reject
  body forms whose generated bytes cannot be known by the signer.
- Protected reference lifecycle routes with the admin verifier, removed
  browser-demo-only revocation state, and required constant-time comparison for
  static admin and promotion tokens of at least 32 bytes.
- Added compiled `dist` output to every npm publish manifest and prepack build;
  built both Python wheels and installed them in a clean environment.
- Pinned CI actions to full commits and the Redis and PostgreSQL services to
  content digests. Moved CI from end-of-life Node 20 to Node 24 LTS, updated
  Node type definitions, and updated the Argon2 binding.
- Fixed PostgreSQL serialization that previously dropped `maxRequests`, ghost
  kind/canary class, cumulative failures, and the first-failure timestamp.
  Pending-registration upserts now also replace their request timestamp.
- Tightened replica import validation for every optional authorization field,
  including usage caps, anomaly state, expiry, pair kind, and canary class.
  Malformed signed state is rejected instead of being persisted for failover.
- Final verification: TypeScript build passed; 171 Node tests passed (27 core,
  125 server, 19 client); 71 Python tests passed (40 client, 31 server);
  cross-language interoperability passed; all three npm dry-run tarballs
  contained compiled output; both Python wheels built and installed; full and
  production-only npm audits reported zero known vulnerabilities; a clean
  Python wheel environment reported no known vulnerabilities.
- A clean `npm ci` reinstall from the root lockfile was followed by a second
  successful build, all 171 Node tests, cross-language integration, and the
  production dependency audit.
- Live Redis verification used two independent clients and 64 concurrent uses:
  exactly one first use succeeded, 63 replays were rejected, TTL behavior
  passed, and the temporary container and listener were removed.
- Live PostgreSQL verification covered migration from the legacy schema, every
  authorization-affecting pair field, pending-record replacement, CRUD,
  revocation, and persistence across a complete connection restart. The
  temporary container and listener were removed.
- Live HTTP verification passed registration, three signed status requests,
  a signed users request, replay denial, scope denial, unknown-pair denial,
  authenticated revocation, revoked-pair denial, key rotation, old-pair denial,
  and new-pair acceptance. The temporary server and listener were removed.
- This work was not committed, pushed, merged, deployed, or described as an
  authorization. Review and an intentional release decision are still required.
- Rollback: revert the resulting hardening commit; parked wording and rationale
  remain in `PARKED.md`, `WHY.md`, and Git history.

## 2026-07-18: Production PostgreSQL transaction adapter for durable outbox

- Added `NodePostgresTransactor`, enforcing `SERIALIZABLE`, verified `BEGIN`,
  server-side statement timeout, verified `COMMIT`, and an internal deadline
  across connection acquisition through commit.
- Failed, aborted, timed-out, or poisoned connections are destroyed instead of
  returned to the pool. Disposal failures have explicit observable outcomes.
- A dispatched `COMMIT` with a lost or malformed response becomes
  `AmbiguousCommitError` with `committed="unknown"`; callers reconcile by
  idempotency key instead of blindly retrying.
- Replaced the real-PostgreSQL harness's bespoke adapter with the production
  class. Verification: 23 focused adapter tests, 286 server tests, TypeScript
  build, package dry-run, and 23 real PostgreSQL 16 checks.
- This is single-node mechanism evidence. Issue #16 remains open for the real
  two-node PostgreSQL and Redis failover/split-brain drill with measured RPO/RTO.

## 2026-07-18: Snapshot asynchronous outbox trust boundaries

- Detached and deep-froze canonical I-JSON snapshots before every asynchronous
  append, delivery, acknowledgement-verification, and receiver-apply boundary.
- Rejected proxies, inherited/accessor/symbol fields, unexpected transport
  fields, non-I-JSON values, and invalid transaction capabilities fail-closed.
- Fixed a publisher double-read in which a changing database-row object could
  validate one mutation and deliver another under the original digest.
- Verification: 40 focused adversarial tests, 295 server tests, TypeScript
  build, and 23 real PostgreSQL 16 checks. Independent review found no remaining
  critical, high, or medium snapshot-boundary blocker.

## 2026-07-18: Transactional encrypted pair authority

- Added `PgTransactionalPairStore`, coupling pair and pending-registration
  changes to ordered durable-outbox records in one `SERIALIZABLE` transaction.
- Classified `secretHash` correctly as operational HMAC key material. Set
  mutations use AES-256-GCM with a fresh nonce and AAD bound to the protocol,
  stream, operation, authority identity, algorithm, and seal-key identifier;
  clear key material is absent from durable replication records.
- Expanded schema version 3 and its catalog manifest to govern the outbox and
  pair-authority tables together. Removed the exported test readiness-token
  bypass and added a package-boundary regression.
- Added a forward-only, transactional v2-to-v3 migration that copies legacy
  authority through the new constraints, attests the complete schema, and only
  then advances the version marker. Invalid legacy data rolls back intact.
- Added a governed standalone-v2 preparation step and a migration-only
  transactor entry that acquires authority locks before establishing the
  serializable snapshot. A deterministic real-PostgreSQL regression proves a
  writer committing while migration waits is preserved or the migration fails.
- Closed normalization aliases and side effects: required values come only from
  own data descriptors, public-key/secret values use canonical 32-byte
  base64url, and sealed payload encodings must round-trip canonically.
- Closed the production transactor escape that allowed callback-issued
  transaction/session control. Callback SQL is now single-statement and
  lexed across comments and quoted literals before dispatch; a real PostgreSQL
  regression proves early COMMIT/ROLLBACK/SAVEPOINT/multi-statement attempts
  leave zero durable rows.
- Verification: TypeScript build, 306 server tests, package-boundary and dry-run
  tarball checks, and 34 integrated PostgreSQL 16 checks.
- This is single-node mechanism evidence. Issue #16 remains open for the real
  two-node PostgreSQL/Redis drill, resynchronization, and measured RPO/RTO.
## 2026-07-18: Atomic pair registry mechanism

- Added `AtomicPairStore` and production enforcement in `PairRegistry`.
- Added transactional PostgreSQL approval, mutation, successful-use claim, and
  rotation operations with compound receiver mutations.
- Removed fire-and-forget expiry/lock persistence and enforced `maxRequests`
  with an atomic claim before authorization succeeds.
- Added concurrent memory-store tests and real PostgreSQL approval, capacity,
  CAS, usage-cap, and compound receiver evidence.
- Bound the final successful-use claim to the complete authorization policy
  snapshot and retained durable expiry/cap reasons for concurrent losers.
- Added middleware regressions for concurrent scope mutation and the final
  usage-cap race; neither denial increments the pair's successful-use count.
- Canonicalized public-key identity identically in middleware, memory, and
  PostgreSQL claims; absent and explicit-undefined optional JWK metadata no
  longer creates a false policy mismatch.
- Validation: 318 server tests, 37 integrated PostgreSQL 16 checks, workspace
  build/tests, package-boundary suite, and dry-pack all pass.
- Issue #16 remains open; this is single-node transactional mechanism evidence,
  not a two-node HA claim.

## 2026-07-18: Authenticated two-state replication hop

- Added the production HTTP implementation of `OutboxTransport` and a bounded
  receiver handler. Request authentication binds the exact method/path and raw
  body digest before a durable nonce is consumed and semantic parsing begins.
- Bound each response to the fresh request attempt in addition to the existing
  signed receiver decision. Lost replies remain ambiguous and retriable; they
  never fabricate an acknowledgement.
- Locked the durable nonce table before its per-request catalog attestation and
  held the lock through nonce insertion, closing the concurrent-DDL gap.
- Made a terminally quarantined row the durable ordered-stream barrier, so a
  fresh publisher cannot skip it and deliver later operations.
- Replaced the two-PostgreSQL drill's in-process adapter with the authenticated
  socket path and recorded zero post-convergence loss plus convergence time.
- This is bounded mechanism evidence; issue #16 remains open.
