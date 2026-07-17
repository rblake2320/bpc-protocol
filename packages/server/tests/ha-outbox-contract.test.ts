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
  epochTransitionDigest,
  fenceTokenToDecimal,
  idempotencyKeyOf,
  streamHeadDigest,
  type OutboxRecordHeader,
} from '../src/ha-outbox-contract.js';

const here = dirname(fileURLToPath(import.meta.url));
const v = JSON.parse(readFileSync(join(here, 'ha-outbox-contract.vectors.json'), 'utf8'));

describe('HA outbox contract v1 (RFC8785/7493, review-hardened)', () => {
  it('vectors match this version + domain', () => {
    expect(v.contractVersion).toBe(HA_OUTBOX_CONTRACT_VERSION);
    expect(v.digestDomain).toBe(HA_OUTBOX_DIGEST_DOMAIN);
  });

  it('reproduces every POSITIVE vector (cross-repo agreement); mutations start at seq>=1', () => {
    for (const p of v.positive) {
      expect(canonicalOpDigest(p), p.name).toBe(p.expectedDigest);
      expect(p.sequence).toBeGreaterThanOrEqual(1);
    }
  });

  it('TAMPER vectors (incl. fence token) change the digest', () => {
    for (const t of v.tamper) {
      expect(canonicalOpDigest(t.base)).toBe(t.baseDigest);
      expect(canonicalOpDigest(t.tampered)).toBe(t.tamperedDigest);
      expect(t.tamperedDigest).not.toBe(t.baseDigest);
    }
  });

  it('epoch-transition and stream-head digests reproduce', () => {
    const e = v.epochTransition;
    expect(epochTransitionDigest(e)).toBe(e.expectedDigest);
    const h = v.streamHead;
    expect(streamHeadDigest(h)).toBe(h.expectedDigest);
  });

  it('(1) lone surrogate is REJECTED and never collides with the replacement char', () => {
    expect(v.loneSurrogate.rejected).toBe(true);
    const base = { streamId: 's/v1', sourceEpoch: 'e1', sequence: 1, fenceToken: '0' };
    expect(() => canonicalOpDigest({ ...base, mutation: { x: '\uD800' } })).toThrow(ContractValidationError);
    expect(() => canonicalize('\uDC00')).toThrow(ContractValidationError);
    // the replacement-char string is valid and hashes to the recorded value
    expect(canonicalOpDigest({ ...v.tamper[0].base, mutation: { x: '�' } })).toBe(v.loneSurrogate.replacementCharDigest);
  });

  it('adversarial rejects (recorded + live)', () => {
    expect(v.reject.every((r: { threw: boolean }) => r.threw)).toBe(true);
    const base = { streamId: 's/v1', sourceEpoch: 'e1', sequence: 1, fenceToken: '5' };
    const cases: Array<() => unknown> = [
      () => canonicalOpDigest({ ...base, mutation: { x: undefined } }),
      () => canonicalOpDigest({ ...base, mutation: { x: 1.5 } }),
      () => canonicalOpDigest({ ...base, mutation: { x: 1n as unknown } }),
      () => canonicalOpDigest({ ...base, mutation: { x: new Date(0) } }),
      () => canonicalOpDigest({ ...base, fenceToken: '007', mutation: {} }),   // (5) leading zero
      () => canonicalOpDigest({ ...base, streamId: 'bad id', mutation: {} }),
      () => canonicalOpDigest({ ...base, mutation: { x: 'a'.repeat((1 << 16) + 1) } }), // (2) oversized
    ];
    for (const f of cases) expect(f).toThrow(ContractValidationError);
  });

  it('(3) symbol keys and accessor/getter properties are rejected', () => {
    const withSym: Record<string | symbol, unknown> = { a: 1 }; withSym[Symbol('s')] = 2;
    expect(() => canonicalize(withSym)).toThrow(ContractValidationError);
    const withGetter = Object.defineProperty({}, 'g', { enumerable: true, get() { return 1; } });
    expect(() => canonicalize(withGetter)).toThrow(ContractValidationError);
    const poison = JSON.parse('{"__proto__": {"a": 1}}');
    expect(() => canonicalize(poison)).toThrow(ContractValidationError);
  });

  it('length-prefixed framing has no separator collision; key order invariant', () => {
    const a = canonicalOpDigest({ streamId: 'a:x/v1', sourceEpoch: 'b', sequence: 0, fenceToken: '0', mutation: {} });
    const b = canonicalOpDigest({ streamId: 'a:x', sourceEpoch: 'v1b', sequence: 0, fenceToken: '0', mutation: {} });
    expect(a).toBe(v.framingNonCollision.digestA);
    expect(b).toBe(v.framingNonCollision.digestB);
    expect(a).not.toBe(b);
    expect(canonicalOpDigest({ ...v.tamper[0].base, sequence: 9, mutation: { a: 1, b: 2 } }))
      .toBe(canonicalOpDigest({ ...v.tamper[0].base, sequence: 9, mutation: { b: 2, a: 1 } }));
  });

  it('(4)(5) assertHeaderConformant validates version/ids/sequence/fence/opDigest-hex', () => {
    const ok: OutboxRecordHeader = { contractVersion: '1', streamId: 's/v1', sourceEpoch: 'e1', sequence: 5, fenceToken: '9', opDigest: 'a'.repeat(64) };
    expect(() => assertHeaderConformant(ok)).not.toThrow();
    expect(() => assertHeaderConformant({ ...ok, contractVersion: '2' as unknown as '1' })).toThrow(ContractValidationError);
    expect(() => assertHeaderConformant({ ...ok, fenceToken: '007' })).toThrow(ContractValidationError);
    expect(() => assertHeaderConformant({ ...ok, opDigest: 'XYZ' })).toThrow(ContractValidationError);
    expect(() => assertHeaderConformant({ ...ok, opDigest: 'A'.repeat(64) })).toThrow(ContractValidationError); // uppercase
    expect(idempotencyKeyOf(ok)).toEqual({ streamId: 's/v1', sourceEpoch: 'e1', sequence: 5 });
  });

  it('fenceTokenToDecimal rejects negatives / non-bigint', () => {
    expect(fenceTokenToDecimal(42n)).toBe('42');
    expect(() => fenceTokenToDecimal(-1n)).toThrow(ContractValidationError);
    expect(() => fenceTokenToDecimal(1 as unknown as bigint)).toThrow(ContractValidationError);
  });
});
