import type { NonceStoreBackend } from './store.js';
import { AuthorizationQuarantineError } from './redis-continuity.js';

export class NonceStoreUnavailableError extends Error {
  readonly code = 'replay_store_unavailable';

  constructor(cause?: unknown) {
    super('Replay store unavailable', { cause });
    this.name = 'NonceStoreUnavailableError';
  }
}

export class ServerNonceStore {
  constructor(
    private backend: NonceStoreBackend,
    private windowMs = 120_000,
  ) {
    if (!Number.isSafeInteger(windowMs) || windowMs <= 0) {
      throw new RangeError('Nonce retention window must be a positive safe integer');
    }
  }

  async checkAndConsume(nonce: string): Promise<boolean> {
    try {
      return await this.backend.checkAndConsume(nonce, this.windowMs);
    } catch (error) {
      if (error instanceof NonceStoreUnavailableError || error instanceof AuthorizationQuarantineError) throw error;
      throw new NonceStoreUnavailableError(error);
    }
  }
}
