/**
 * COMPILE-TIME contract proof (blocker 1): `canonicalOpDigest` accepts ONLY a
 * `SanitizedMutation<Clean>`. A raw payload — e.g. one still carrying a secret —
 * is a TYPE ERROR, so "sanitize before digest" is structurally enforced, not
 * merely observed in a runtime test. Typechecked via
 * `tsconfig.contract-typecheck.json`; if the generic guard were removed the
 * `@ts-expect-error` below would become an unused-directive error and fail CI.
 */
import { canonicalOpDigest, type SanitizedMutation } from '../src/ha-outbox-contract.js';

interface Clean {
  pairId: string;
}
interface Raw {
  pairId: string;
  secret: string;
}

const sanitized = { pairId: 'p1' } as SanitizedMutation<Clean>;
// OK: a sanitizer-produced value is accepted.
void canonicalOpDigest({ streamId: 's/v1', sourceEpoch: 'e1', sequence: 1, fenceToken: '1', mutation: sanitized });

const raw: Raw = { pairId: 'p1', secret: 'TOP' };
// @ts-expect-error a raw (non-sanitized) mutation must NOT be assignable to SanitizedMutation.
void canonicalOpDigest({ streamId: 's/v1', sourceEpoch: 'e1', sequence: 1, fenceToken: '1', mutation: raw });

// @ts-expect-error a plain object literal (no sanitizer brand) is rejected too.
void canonicalOpDigest({ streamId: 's/v1', sourceEpoch: 'e1', sequence: 1, fenceToken: '1', mutation: { pairId: 'p1' } });
