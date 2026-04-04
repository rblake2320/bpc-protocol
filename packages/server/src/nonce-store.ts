import type { NonceStoreBackend } from './store.js';

export class ServerNonceStore {
  constructor(
    private backend: NonceStoreBackend,
    private windowMs = 120_000,
  ) {}

  async checkAndConsume(nonce: string): Promise<boolean> {
    return this.backend.checkAndConsume(nonce, this.windowMs);
  }
}
