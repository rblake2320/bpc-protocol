# Change Log

## 2026-07-16

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
  all passed. PostgreSQL was not listening locally and remains a hosted-CI gate.
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
