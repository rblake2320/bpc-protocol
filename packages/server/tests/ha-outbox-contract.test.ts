import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';

import {
  HA_OUTBOX_CONTRACT_VERSION,
  HA_OUTBOX_DIGEST_DOMAIN,
  ContractValidationError,
  assertHeaderConformant,
  assertStreamHeadBinds,
  canonicalOpDigest,
  canonicalize,
  epochTransitionDigest,
  fenceTokenToDecimal,
  idempotencyKeyOf,
  streamHeadDigest,
  type MutationSanitizer,
  type OutboxRecordHeader,
  type SanitizedMutation,
  type SignedStreamHead,
} from '../src/ha-outbox-contract.js';

const here = dirname(fileURLToPath(import.meta.url));
const v = JSON.parse(readFileSync(join(here, 'ha-outbox-contract.vectors.json'), 'utf8'));

describe('HA outbox contract v1 (RFC8785/7493, final-review hardened)', () => {
  it('vectors match version + domain', () => {
    expect(v.contractVersion).toBe(HA_OUTBOX_CONTRACT_VERSION);
    expect(v.digestDomain).toBe(HA_OUTBOX_DIGEST_DOMAIN);
  });

  it('reproduces POSITIVE vectors (mutations seq>=1)', () => {
    for (const p of v.positive) { expect(canonicalOpDigest(p), p.name).toBe(p.expectedDigest); expect(p.sequence).toBeGreaterThanOrEqual(1); }
  });

  it('(4) sequence-0 mutation is rejected (genesis is typed-separate)', () => {
    expect(() => canonicalOpDigest({ streamId: 's/v1', sourceEpoch: 'e1', sequence: 0, fenceToken: '0', mutation: {} })).toThrow(ContractValidationError);
  });

  it('TAMPER vectors change the digest', () => {
    for (const t of v.tamper) { expect(canonicalOpDigest(t.tampered)).toBe(t.tamperedDigest); expect(t.tamperedDigest).not.toBe(t.baseDigest); }
  });

  it('epoch-transition (forward index + snapshot digest) and stream-head (keyId+alg) digests reproduce', () => {
    expect(epochTransitionDigest(v.epochTransition)).toBe(v.epochTransition.expectedDigest);
    expect(streamHeadDigest(v.streamHead)).toBe(v.streamHead.expectedDigest);
  });

  it('(9) epoch transition rejects same/backward/arbitrary', () => {
    const b = v.epochTransition;
    expect(() => epochTransitionDigest({ ...b, toEpoch: b.fromEpoch })).toThrow(ContractValidationError); // same
    expect(() => epochTransitionDigest({ ...b, toEpochIndex: b.fromEpochIndex })).toThrow(ContractValidationError); // not forward
    expect(() => epochTransitionDigest({ ...b, snapshotDigest: 'nope' })).toThrow(ContractValidationError); // bad snapshot digest
  });

  it('(3) stream head binds exactly to the record; wrong field rejected', () => {
    const rec: OutboxRecordHeader = { contractVersion: '1', streamId: v.streamHead.streamId, sourceEpoch: 'e7', sequence: v.streamHead.sequence, fenceToken: '1', opDigest: v.streamHead.opDigest };
    const head: SignedStreamHead = { streamId: v.streamHead.streamId, sequence: v.streamHead.sequence, prevHeadDigest: v.streamHead.prevHeadDigest, opDigest: v.streamHead.opDigest, keyId: v.streamHead.keyId, alg: v.streamHead.alg, headDigest: v.streamHead.expectedDigest, signature: 'sig' };
    expect(() => assertStreamHeadBinds(rec, head)).not.toThrow();
    expect(() => assertStreamHeadBinds({ ...rec, opDigest: 'a'.repeat(64) }, head)).toThrow(ContractValidationError);
    expect(() => assertStreamHeadBinds(rec, { ...head, sequence: head.sequence + 1 })).toThrow(ContractValidationError);
    expect(() => assertStreamHeadBinds(rec, { ...head, alg: 'bogus' as never })).toThrow(ContractValidationError);
    expect(() => assertStreamHeadBinds(rec, { ...head, headDigest: 'b'.repeat(64) })).toThrow(ContractValidationError);
  });

  it('(1)(7) lone surrogate rejected, no replacement-char collision', () => {
    expect(v.loneSurrogate.rejected).toBe(true);
    expect(() => canonicalize('\uDC00')).toThrow(ContractValidationError);
    expect(canonicalOpDigest({ ...v.tamper[0].base, mutation: { x: '�' } })).toBe(v.loneSurrogate.replacementCharDigest);
  });

  it('(1)(7) arrays: only dense data indices + length; objects: enumerable data only', () => {
    const arrExtra = [1, 2] as unknown as Record<string, unknown>; (arrExtra as { foo?: number }).foo = 3;
    expect(() => canonicalize(arrExtra)).toThrow(ContractValidationError);
    const arrGetter: unknown[] = [1]; Object.defineProperty(arrGetter, 1, { enumerable: true, get() { return 9; } });
    expect(() => canonicalize(arrGetter)).toThrow(ContractValidationError);
    const nonEnum = Object.defineProperty({ a: 1 }, 'hidden', { enumerable: false, value: 2 });
    expect(() => canonicalize(nonEnum)).toThrow(ContractValidationError);
    const sym: Record<string | symbol, unknown> = { a: 1 }; sym[Symbol('s')] = 2;
    expect(() => canonicalize(sym)).toThrow(ContractValidationError);
    expect(() => canonicalize(JSON.parse('{"__proto__":{"a":1}}'))).toThrow(ContractValidationError);
  });

  it('adversarial reject vectors all recorded as thrown', () => {
    expect(v.reject.every((r: { threw: boolean }) => r.threw)).toBe(true);
  });

  it('(4)(5) assertHeaderConformant validates version/ids/seq/fence/opDigest-hex', () => {
    const ok: OutboxRecordHeader = { contractVersion: '1', streamId: 's/v1', sourceEpoch: 'e1', sequence: 5, fenceToken: '9', opDigest: 'a'.repeat(64) };
    expect(() => assertHeaderConformant(ok)).not.toThrow();
    expect(() => assertHeaderConformant({ ...ok, fenceToken: '007' })).toThrow(ContractValidationError);
    expect(() => assertHeaderConformant({ ...ok, opDigest: 'A'.repeat(64) })).toThrow(ContractValidationError);
    expect(idempotencyKeyOf(ok)).toEqual({ streamId: 's/v1', sourceEpoch: 'e1', sequence: 5 });
  });

  it('fenceTokenToDecimal rejects negatives / non-bigint', () => {
    expect(fenceTokenToDecimal(42n)).toBe('42');
    expect(() => fenceTokenToDecimal(-1n)).toThrow(ContractValidationError);
  });

  // (10) Executable sanitize-before-digest / apply ordering fixture.
  it('(10) sanitize strips the secret BEFORE digest; digesting raw-with-secret differs; receiver rejects unsanitized', () => {
    interface Raw { pairId: string; secret: string }
    interface Clean { pairId: string }
    const sanitizer: MutationSanitizer<Raw, Clean> = {
      sanitize(raw) {
        if (typeof raw.pairId !== 'string') throw new ContractValidationError('bad pairId');
        return { pairId: raw.pairId } as SanitizedMutation<Clean>; // secret stripped
      },
      assertSanitized(c): asserts c is SanitizedMutation<Clean> {
        if (!c || typeof c !== 'object' || 'secret' in (c as object)) throw new ContractValidationError('unsanitized: secret present');
      },
    };
    const raw: Raw = { pairId: 'p1', secret: 'TOP' };
    const clean = sanitizer.sanitize(raw);
    const base = { streamId: 's/v1', sourceEpoch: 'e1', sequence: 1, fenceToken: '1' };
    const digRaw = canonicalOpDigest({ ...base, mutation: raw as unknown });
    const digClean = canonicalOpDigest({ ...base, mutation: clean });
    expect(digRaw).not.toBe(digClean); // secret changes the digest → must sanitize first
    expect(() => sanitizer.assertSanitized(raw)).toThrow(ContractValidationError); // receiver rejects unsanitized
    expect(() => sanitizer.assertSanitized(clean)).not.toThrow();
  });
});
