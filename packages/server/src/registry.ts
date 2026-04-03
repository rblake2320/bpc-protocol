import type { StoredPair, PairRegistration } from './types.js';
import { generateId } from '@bpc/core';

export class PairRegistry {
  private pairs = new Map<string, StoredPair>();
  private pendingApprovals = new Map<string, { registration: PairRegistration; requestedAt: number }>();

  /** Submit a pairing request. Returns approval token. Owner must call approve(token). */
  requestPairing(registration: PairRegistration): string {
    const token = generateId('approval');
    this.pendingApprovals.set(token, { registration, requestedAt: Date.now() });
    return token;
  }

  /** Owner approves a pending pairing. Returns the new pair ID. */
  approvePairing(token: string): string {
    const pending = this.pendingApprovals.get(token);
    if (!pending) throw new Error(`No pending approval for token: ${token}`);
    this.pendingApprovals.delete(token);

    const pairId = generateId('pair');
    const pair: StoredPair = {
      id: pairId,
      ...pending.registration,
      status: 'active',
      created: Date.now(),
      lastActive: null,
      requests: 0,
      failedSigs: 0,
    };
    this.pairs.set(pairId, pair);
    return pairId;
  }

  /** Development mode: auto-approve without owner action. */
  registerDirect(registration: PairRegistration): string {
    const token = this.requestPairing(registration);
    return this.approvePairing(token);
  }

  get(pairId: string): StoredPair | undefined {
    return this.pairs.get(pairId);
  }

  revoke(pairId: string): void {
    const pair = this.pairs.get(pairId);
    if (pair) pair.status = 'revoked';
  }

  list(): StoredPair[] {
    return Array.from(this.pairs.values());
  }

  listPending(): Array<{ token: string; registration: PairRegistration; requestedAt: number }> {
    return Array.from(this.pendingApprovals.entries()).map(([token, v]) => ({ token, ...v }));
  }

  recordActivity(pairId: string, success: boolean): void {
    const pair = this.pairs.get(pairId);
    if (!pair) return;
    pair.requests++;
    pair.lastActive = Date.now();
    if (!success) pair.failedSigs++;
  }
}
