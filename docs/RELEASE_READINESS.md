# Release readiness

This repository is a protocol/library product. A tag or npm publication is not
evidence that an adopter's deployment is secure, compliant, or certified.

## Required repository gates

Run these on the candidate commit:

```powershell
npm ci
npm run build
npm test
npm run test:adversarial
npm run test:interop
npm run test:installed
npm run test:integration
```

The CI workflow also runs the Redis and PostgreSQL adapter tests in disposable
service containers. A release should record the commit SHA and retained CI
artifacts for these commands.

## Required product decisions before commercial deployment

1. Select an owner-supported deployment topology, including Redis durability,
   PostgreSQL backup/restore, key/secrets management, monitoring, and incident
   response. The in-memory factories are development/test utilities.
2. Select an authenticated production pairing/approval flow. Never expose
   `registerDirect()` as an unauthenticated endpoint.
3. Decide the supported BPC/TSK version pair and pin it in the deployer’s lock
   file. Run the TSK bridge compatibility suite against those exact artifacts.
4. Publish support terms, upgrade/rotation policy, data retention/deletion
   policy, vulnerability reporting channel, and a documented rollback path.
5. Obtain any required independent security assessment and legal/privacy review
   before making regulated-industry, compliance, hardware-binding, or product
   certification claims.

## Explicit non-claims

Passing these gates does not establish FIPS validation, an ATO, HIPAA/GDPR/PCI
compliance, hardware attestation, protection after verifier-host compromise, or
post-quantum security. Those are deployment- and assessment-specific claims.
