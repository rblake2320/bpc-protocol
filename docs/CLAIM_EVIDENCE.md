# Product claim evidence

This file defines what the repository may claim. Anything outside this table is
either a deployment responsibility, a legal/assessment question, or unknown.

| Claim | Evidence | Allowed wording |
|---|---|---|
| BPC runs without an LLM or AI harness | Plain-shell builds, unit/adversarial/interop tests, installed-package smoke test, and Redis/PostgreSQL integration test all execute without a model endpoint. | “BPC verification and SDKs run without an LLM or AI harness.” |
| BPC signs and verifies request-bound credentials | `npm test`, `npm run test:adversarial`, `npm run test:interop`, and `npm run test:installed`. | “The tested implementation signs requests and verifies the configured key, secret HMAC, timestamp, nonce, method, path, body hash, and closed scope.” |
| Distributed replay denial works with Redis | `npm run test:integration` starts isolated Redis and observes one winner / 63 replay denials. | “The Redis adapter was tested against isolated Redis for concurrent first-use replay denial.” |
| Pair persistence works with PostgreSQL | `npm run test:integration` starts isolated PostgreSQL and observes migration plus reconnect persistence. | “The PostgreSQL pair store was tested against an isolated PostgreSQL service.” |
| BPC composes with TSK | Reviewed TSK `test:bpc-compat` passed 10/10 against this checkout. | “The reviewed BPC/TSK bridge test accepted an identity-bound request and denied a BPC replay before TSK validation.” |

## Prohibited or unverified claims

- Do not claim a patent is pending, granted, or covers this implementation
  unless the owner supplies a verified application or patent reference and legal
  review approves the exact wording.
- Do not claim compliance, certification, hardware binding, protection after
  endpoint or verifier-host compromise, universal attack prevention, or that a
  test suite proves a deployment is secure.
- Do not represent the demo TSK flow as the maintained TSK product integration;
  use `@tsk/bpc-bridge` and [TSK composition](TSK_COMPOSITION.md).

Commercial claim review must occur before advertising. The FTC says advertising
must be truthful, non-deceptive, and supported by evidence; it evaluates both
express and implied claims. See the [FTC advertising FAQ](https://www.ftc.gov/business-guidance/resources/advertising-faqs-guide-small-business).
Patent status requires a separate owner/legal verification. The USPTO explains
that filing and examination do not guarantee issuance; see its [patent process
overview](https://www.uspto.gov/patents/basics/patent-process-overview).

## Claim gate

`npm run test:claims` scans both public demo pages for prohibited patent,
compromise, and regulated-industry language. CI runs it for every change.
