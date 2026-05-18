/**
 * BPC Pair Registry
 *
 * Security hardening (IL4-7):
 *
 *  BPC-04 FIX — Unauthenticated Pair Enumeration:
 *    Added `listRedacted()` which returns pairs with sensitive fields removed
 *    (secretHash, pubJwk, failedSigs, expiresAt). The server layer MUST use
 *    this method for any publicly-accessible listing endpoint.
 *
 *  Registration hardening (BPC-01 source fix):
 *    - Empty secretHash rejected at registration time.
 *    - secretHash minimum length enforced (43 chars = 256-bit HKDF output).
 *    - Pair name length, scope, and mode validated.
 *
 *  NIST SP 800-53 Rev 5 controls: AC-2, AC-3, IA-5, SI-10.
 */

import { generateId } from '@bpc/core';
import type { PairStore } from './store.js';
import type { StoredPair, PairRegistration } from './types.js';

/** Minimum secretHash length: 43 chars = 256-bit HKDF output in base64url. */
const MIN_SECRET_HASH_LEN = 43;

/** Maximum pair name length. */
const MAX_NAME_LEN = 128;

/** Allowed scope values. */
const ALLOWED_SCOPES = new Set(['read', 'read-write', 'admin']);

/** Allowed mode values. */
const ALLOWED_MODES = new Set(['development', 'production']);

/** Redacted pair — safe for admin/public listing. Strips all sensitive fields. */
export interface RedactedPair {
  id: string;
  name: string;
  scope: string;
  mode: string;
  status: string;
  created: number;
  lastActive: number | null;
  requests: number;
}

export class PairRegistry {
  private store: PairStore;
  private maxPairs: number;
  private lockoutCount: number;

  constructor(store: PairStore, maxPairs = 2000, lockoutCount = 10) {
    this.store = store;
    this.maxPairs = maxPairs;
    this.lockoutCount = lockoutCount;
  }

  /**
   * Validate a PairRegistration before accepting it.
   * BPC-04 / BPC-01 hardening: rejects empty or short secretHash at source.
   */
  private validateRegistration(registration: PairRegistration): void {
    if (!registration.secretHash || registration.secretHash.length < MIN_SECRET_HASH_LEN) {
      throw new Error(
        `Registration rejected: secretHash must be at least ${MIN_SECRET_HASH_LEN} characters. ` +
        `Use hashSecret() to derive a proper HKDF key from your secret.`,
      );
    }
    if (!registration.name || typeof registration.name !== 'string') {
      throw new Error('Registration rejected: name is required');
    }
    if (registration.name.length > MAX_NAME_LEN) {
      throw new Error(`Registration rejected: name must be at most ${MAX_NAME_LEN} characters`);
    }
    if (!ALLOWED_SCOPES.has(registration.scope)) {
      throw new Error(`Registration rejected: scope must be one of: ${[...ALLOWED_SCOPES].join(', ')}`);
    }
    if (!ALLOWED_MODES.has(registration.mode)) {
      throw new Error(`Registration rejected: mode must be one of: ${[...ALLOWED_MODES].join(', ')}`);
    }
    if (!registration.pubJwk || typeof registration.pubJwk !== 'object') {
      throw new Error('Registration rejected: pubJwk is required');
    }
  }

  async requestPairing(registration: PairRegistration): Promise<string> {
    this.validateRegistration(registration);
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

  /** Full pair list — for internal/privileged use only. Never expose directly over HTTP. */
  async list(): Promise<StoredPair[]> {
    return this.store.list();
  }

  /**
   * Redacted pair list — safe for admin dashboard or authenticated listing endpoints.
   *
   * BPC-04 FIX: Strips secretHash, pubJwk, failedSigs, and expiresAt so that
   * sensitive cryptographic material is never returned over the wire.
   */
  async listRedacted(): Promise<RedactedPair[]> {
    const pairs = await this.store.list();
    return pairs.map(p => ({
      id:         p.id,
      name:       p.name,
      scope:      p.scope,
      mode:       p.mode,
      status:     p.status,
      created:    p.created,
      lastActive: p.lastActive,
      requests:   p.requests,
    }));
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
