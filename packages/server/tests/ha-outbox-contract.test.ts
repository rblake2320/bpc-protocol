import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';

import {
  HA_OUTBOX_CONTRACT_VERSION,
  HA_OUTBOX_DIGEST_DOMAIN,
  ContractValidationError,
  assertHeaderConformant,
  canonicalOpDigest,
  canonicalize,
  idempotencyKeyOf,
  type OutboxRecordHeader,
} from '../src/ha-outbox-contract.js';

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(join(here, 'ha-outbox-contract.vectors.json'), 'utf8')) as {
  contractVersion: string;
  digestDomain: string;
  positive: Array<{ name: string; streamId: string; sourceEpoch: string; sequence: number; mutation: unknown; expectedDigest: string }>;
  tamper: Array<{ name: string; base: any; tampered: any; baseDigest: string; tamperedDigest: string }>;
  reject: Array<{ name: string; input: any; mustReject: boolean }>;
  framingNonCollision: { digestA: string; digestB: string; mustDiffer: boolean };
  keyOrderInvariant: { digestA: string; digestB: string; mustEqual: boolean };
};

describe('HA outbox contract — canonical digest (shared bpc/tsk, RFC8785/7493)', () => {
  it('vectors match this version + domain', () => {
    expect(vectors.contractVersion).toBe(HA_OUTBOX_CONTRACT_VERSION);
    expect(vectors.digestDomain).toBe(HA_OUTBOX_DIGEST_DOMAIN);
  });

  it('reproduces every POSITIVE vector (cross-repo agreement)', () => {
    for (const v of vectors.positive) expect(canonicalOpDigest(v), v.name).toBe(v.expectedDigest);
  });

  it('TAMPER vectors change the digest', () => {
    for (const t of vectors.tamper) {
      expect(canonicalOpDigest(t.base), `${t.name} base`).toBe(t.baseDigest);
      expect(canonicalOpDigest(t.tampered), `${t.name} tampered`).toBe(t.tamperedDigest);
      expect(t.tamperedDigest).not.toBe(t.baseDigest);
    }
  });

  it('ADVERSARIAL reject cases all throw (recorded in vectors + re-run live)', () => {
    // The vectors file records that every reject case threw at generation time.
    // (Their inputs cannot round-trip through JSON — undefined/bigint/Date/etc.
    // are lossy — so the live inputs are reconstructed here.)
    expect(vectors.reject.every((r) => (r as { threw?: boolean }).threw === true)).toBe(true);
    const base = { streamId: 's/v1', sourceEpoch: 'e1', sequence: 0 };
    const cases: Array<[string, () => string]> = [
      ['undefined-value', () => canonicalOpDigest({ ...base, mutation: { x: undefined } })],
      ['float', () => canonicalOpDigest({ ...base, mutation: { x: 1.5 } })],
      ['infinity', () => canonicalOpDigest({ ...base, mutation: { x: Infinity } })],
      ['bigint', () => canonicalOpDigest({ ...base, mutation: { x: 1n } })],
      ['date', () => canonicalOpDigest({ ...base, mutation: { x: new Date(0) } })],
      ['sparse-array', () => { const a = [1]; a[3] = 2; return canonicalOpDigest({ ...base, mutation: { x: a } }); }],
      ['bad-streamId-space', () => canonicalOpDigest({ streamId: 'bad id', sourceEpoch: 'e1', sequence: 0, mutation: {} })],
      ['neg-sequence', () => canonicalOpDigest({ ...base, sequence: -1, mutation: {} })],
    ];
    for (const [name, fn] of cases) expect(fn, name).toThrow(ContractValidationError);
  });

  it('length-prefixed framing has no separator collision', () => {
    const a = canonicalOpDigest({ streamId: 'a:x/v1', sourceEpoch: 'b', sequence: 0, mutation: {} });
    const b = canonicalOpDigest({ streamId: 'a:x', sourceEpoch: 'v1b', sequence: 0, mutation: {} });
    expect(a).toBe(vectors.framingNonCollision.digestA);
    expect(b).toBe(vectors.framingNonCollision.digestB);
    expect(a).not.toBe(b);
  });

  it('digest is independent of mutation key order', () => {
    const a = canonicalOpDigest({ streamId: 's/v1', sourceEpoch: 'e1', sequence: 9, mutation: { a: 1, b: 2 } });
    const b = canonicalOpDigest({ streamId: 's/v1', sourceEpoch: 'e1', sequence: 9, mutation: { b: 2, a: 1 } });
    expect(a).toBe(b);
    expect(a).toBe(vectors.keyOrderInvariant.digestA);
  });

  it('canonicalize rejects non-I-JSON directly', () => {
    for (const bad of [undefined, 1.5, Infinity, NaN, 1n, () => 0, Symbol('s'), new Date(), new Map()]) {
      expect(() => canonicalize({ x: bad as unknown }), String(bad)).toThrow(ContractValidationError);
    }
    // __proto__ own key
    const poison = JSON.parse('{"__proto__": {"a": 1}}');
    expect(() => canonicalize(poison)).toThrow(ContractValidationError);
  });

  it('assertHeaderConformant rejects bad version / ids / sequence', () => {
    const ok: OutboxRecordHeader = { contractVersion: '1', streamId: 's/v1', sourceEpoch: 'e1', sequence: 5, opDigest: 'x' };
    expect(() => assertHeaderConformant(ok)).not.toThrow();
    expect(() => assertHeaderConformant({ ...ok, contractVersion: '2' as unknown as '1' })).toThrow(ContractValidationError);
    expect(() => assertHeaderConformant({ ...ok, streamId: 'bad id' })).toThrow(ContractValidationError);
    expect(() => assertHeaderConformant({ ...ok, sequence: -1 })).toThrow(ContractValidationError);
    expect(idempotencyKeyOf(ok)).toEqual({ streamId: 's/v1', sourceEpoch: 'e1', sequence: 5 });
  });
});
