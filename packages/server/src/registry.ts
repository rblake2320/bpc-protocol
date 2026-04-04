import { generateId } from '@bpc/core';
import type { PairStore } from './store.js';
import type { StoredPair, PairRegistration } from './types.js';

export class PairRegistry {
  private store: PairStore;
  private maxPairs: number;
  private lockoutCount: number;

  constructor(store: PairStore, maxPairs = 2000, lockoutCount = 10) {
    this.store = store;
    this.maxPairs = maxPairs;
    this.lockoutCount = lockoutCount;
  }

  async requestPairing(registration: PairRegistration): Promise<string> {
    const pairs = await this.store.list();
    if (pairs.filter(p => p.status === 'active').length >= this.maxPairs) {
      throw new Error(`Maximum pair capacity (${this.maxPairs}) reached`);
    }
    const token = generateId('approval');
    await this.store.setPending(token, registration, Date.now());
    return token;
  }

  async approvePairing(token: string): Promise<string> {
    const pending = await this.store.getPending(token);
    if (!pending) throw new Error(`No pending approval for token: ${token}`);
    await this.store.deletePending(token);

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
    await this.store.set(pair);
    return pairId;
  }

  async registerDirect(registration: PairRegistration): Promise<string> {
    const token = await this.requestPairing(registration);
    return this.approvePairing(token);
  }

  async get(pairId: string): Promise<StoredPair | undefined> {
    return this.store.get(pairId);
  }

  async revoke(pairId: string): Promise<void> {
    const pair = await this.store.get(pairId);
    if (pair) {
      pair.status = 'revoked';
      await this.store.set(pair);
    }
  }

  async list(): Promise<StoredPair[]> {
    return this.store.list();
  }

  async listPending() {
    return this.store.listPending();
  }

  async recordActivity(pairId: string, success: boolean): Promise<void> {
    const pair = await this.store.get(pairId);
    if (!pair) return;
    pair.requests++;
    pair.lastActive = Date.now();
    if (!success) {
      pair.failedSigs++;
      // Auto-lockout after threshold
      if (pair.failedSigs >= this.lockoutCount && pair.status === 'active') {
        pair.status = 'locked';
      }
    }
    await this.store.set(pair);
  }

  async unlock(pairId: string): Promise<void> {
    const pair = await this.store.get(pairId);
    if (pair && pair.status === 'locked') {
      pair.status = 'active';
      pair.failedSigs = 0;
      await this.store.set(pair);
    }
  }
}
