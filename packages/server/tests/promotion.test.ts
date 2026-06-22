import { describe, it, expect } from 'vitest';
import {
  PromotionController, assertWritable, handlePromotionCommand,
} from '../src/promotion.js';

const GUARD = 'guard-token-xyz';

describe('PromotionController PR-01 single-writer invariant', () => {
  it('a primary is always writable and cannot be promoted/demoted', () => {
    const p = new PromotionController('primary');
    expect(p.isWritable()).toBe(true);
    expect(() => p.promote('guard')).toThrow();
    expect(() => p.demote('guard')).toThrow();
  });

  it('a fresh replica is NOT writable (fail-closed default)', () => {
    const r = new PromotionController('replica');
    expect(r.isWritable()).toBe(false);
    expect(assertWritable(r)).toEqual({ ok: false, status: 503, error: 'replica_not_promoted' });
  });

  it('a promoted replica becomes writable; demotion reverts it', () => {
    const r = new PromotionController('replica');
    r.promote('fleet-guard', 'primary down');
    expect(r.isWritable()).toBe(true);
    expect(assertWritable(r)).toEqual({ ok: true });
    const snap = r.snapshot();
    expect(snap.promoted).toBe(true);
    expect(snap.promotedBy).toBe('fleet-guard');
    expect(snap.reason).toBe('primary down');

    r.demote('fleet-guard', 'primary recovered');
    expect(r.isWritable()).toBe(false);
    expect(assertWritable(r).ok).toBe(false);
  });
});

describe('PR-02 explicit demotion (no auto fail-back)', () => {
  it('promoted state never auto-clears — only an explicit demote flips it', () => {
    const r = new PromotionController('replica');
    r.promote('guard');
    // No timer, no auto-expiry — still writable until explicitly demoted.
    expect(r.isWritable()).toBe(true);
    expect(r.isWritable()).toBe(true);
    r.demote('guard');
    expect(r.isWritable()).toBe(false);
  });
});

describe('PR-03 guard-only control via admin command', () => {
  it('rejects a promote command without the guard token (401)', () => {
    const r = new PromotionController('replica');
    const res = handlePromotionCommand(r, { 'x-guard-token': 'wrong' }, { command: 'promote', by: 'x' }, GUARD);
    expect(res.status).toBe(401);
    expect(r.isWritable()).toBe(false);     // unchanged
  });

  it('rejects a missing token (401)', () => {
    const r = new PromotionController('replica');
    expect(handlePromotionCommand(r, {}, { command: 'promote', by: 'x' }, GUARD).status).toBe(401);
  });

  it('promotes with valid guard token (200) and returns a snapshot', () => {
    const r = new PromotionController('replica');
    const res = handlePromotionCommand(r, { 'x-guard-token': GUARD }, { command: 'promote', by: 'guard-1', reason: 'failover' }, GUARD) as any;
    expect(res.status).toBe(200);
    expect(res.result.ok).toBe(true);
    expect(res.result.snapshot.writable).toBe(true);
    expect(r.isWritable()).toBe(true);
  });

  it('rejects an invalid command (400) and a missing actor (400)', () => {
    const r = new PromotionController('replica');
    expect(handlePromotionCommand(r, { 'x-guard-token': GUARD }, { command: 'nuke', by: 'x' }, GUARD).status).toBe(400);
    expect(handlePromotionCommand(r, { 'x-guard-token': GUARD }, { command: 'promote' }, GUARD).status).toBe(400);
  });

  it('promote on a primary returns 409 (conflict), not a crash', () => {
    const p = new PromotionController('primary');
    const res = handlePromotionCommand(p, { 'x-guard-token': GUARD }, { command: 'promote', by: 'guard' }, GUARD);
    expect(res.status).toBe(409);
  });

  it('demote via command flips a promoted replica back to read-only', () => {
    const r = new PromotionController('replica');
    r.promote('guard');
    const res = handlePromotionCommand(r, { 'x-guard-token': GUARD }, { command: 'demote', by: 'guard', reason: 'recovered' }, GUARD) as any;
    expect(res.status).toBe(200);
    expect(res.result.snapshot.writable).toBe(false);
    expect(r.isWritable()).toBe(false);
  });
});
