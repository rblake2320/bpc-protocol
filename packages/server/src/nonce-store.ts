import { NonceStore } from '@bpc/core';

export class ServerNonceStore {
  private store: NonceStore;

  constructor(windowMs = 120_000) {
    this.store = new NonceStore(windowMs);
  }

  /** Returns true if nonce was already seen (replay). */
  checkAndConsume(nonce: string): boolean {
    if (this.store.has(nonce)) return true; // replay detected
    this.store.add(nonce);
    return false;
  }
}
