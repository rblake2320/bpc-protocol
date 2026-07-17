import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';

import {
  HA_OUTBOX_CONTRACT_VERSION,
  HA_OUTBOX_DIGEST_DOMAIN,
  canonicalOpDigest,
  idempotencyKeyOf,
  type OutboxRecordHeader,
} from '../src/ha-outbox-contract.js';

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(
  readFileSync(join(here, 'ha-outbox-contract.vectors.json'), 'utf8'),
) as {
  contractVersion: string;
  digestDomain: string;
  positive: Array<{ name: string; streamId: string; sourceEpoch: string; sequence: number; mutation: unknown; expectedDigest: string }>;
  tamper: Array<{ name: string; base: any; tampered: any; baseDigest: string; tamperedDigest: string }>;
  keyOrderInvariant: { digestA: string; digestB: string; mustEqual: boolean };
};

describe('HA outbox contract — canonical digest vectors (shared bpc/tsk)', () => {
  it('the vectors were generated for this contract version + domain', () => {
    expect(vectors.contractVersion).toBe(HA_OUTBOX_CONTRACT_VERSION);
    expect(vectors.digestDomain).toBe(HA_OUTBOX_DIGEST_DOMAIN);
  });

  it('reference digest reproduces every POSITIVE vector (cross-repo agreement)', () => {
    for (const v of vectors.positive) {
      expect(canonicalOpDigest(v), v.name).toBe(v.expectedDigest);
    }
  });

  it('TAMPER vectors change the digest (integrity)', () => {
    for (const t of vectors.tamper) {
      expect(canonicalOpDigest(t.base), `${t.name} base`).toBe(t.baseDigest);
      expect(canonicalOpDigest(t.tampered), `${t.name} tampered`).toBe(t.tamperedDigest);
      expect(t.tamperedDigest, t.name).not.toBe(t.baseDigest);
    }
  });

  it('digest is independent of mutation key order', () => {
    const a = canonicalOpDigest({ streamId: 's/v1', sourceEpoch: 'e1', sequence: 9, mutation: { a: 1, b: 2 } });
    const b = canonicalOpDigest({ streamId: 's/v1', sourceEpoch: 'e1', sequence: 9, mutation: { b: 2, a: 1 } });
    expect(a).toBe(b);
    expect(a).toBe(vectors.keyOrderInvariant.digestA);
  });

  it('rejects a non-finite / negative sequence (schema guard)', () => {
    expect(() => canonicalOpDigest({ streamId: 's/v1', sourceEpoch: 'e1', sequence: -1, mutation: {} })).toThrow(RangeError);
    expect(() => canonicalOpDigest({ streamId: 's/v1', sourceEpoch: 'e1', sequence: 1, mutation: { x: Infinity } })).toThrow(RangeError);
  });

  it('idempotency key is exactly (streamId, sourceEpoch, sequence)', () => {
    const h: OutboxRecordHeader = {
      contractVersion: '1', streamId: 's/v1', sourceEpoch: 'e1', sequence: 5, opDigest: 'x',
    };
    expect(idempotencyKeyOf(h)).toEqual({ streamId: 's/v1', sourceEpoch: 'e1', sequence: 5 });
  });
});
