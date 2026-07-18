/**
 * BPC Pair Registry
 *
 * Security hardening:
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
 *  REG-01 FIX — updatePair() mutable reference leak:
 *    updatePair() now returns structuredClone(pair) instead of the live
 *    reference that was written to the store. Callers can no longer
 *    mutate the stored record by mutating the returned object.
 *
 *  REG-02 FIX — ipFailureTracker unbounded memory:
 *    evictStaleIpEntries() removes entries whose window has expired.
 *    Called lazily on every recordActivity() so stale entries are
 *    reclaimed without a background timer or unbounded accumulation.
 *
 *  NIST SP 800-53 Rev 5 controls: AC-2, AC-3, IA-5, SI-10.
 */

import { generateId } from '@bpc/core';
import { isAtomicPairStore, type AtomicPairStore, type PairStore } from './store.js';
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
  private atomicStore?: AtomicPairStore;
  private maxPairs: number;
  private lockoutCount: number;

  /**
   * BPC-09 FIX — Attacker-Induced Lockout DoS:
   * Track unauthenticated failures per IP address. A pair is only locked
   * when the SAME IP accumulates >= lockoutCount failures within the window.
   * An attacker from a different IP cannot lock a victim's pair.
   * Key: `${pairId}:${ip}`, Value: { count, windowStart }.
   *
   * REG-02 FIX: entries are lazily evicted once their window expires so the
   * map cannot grow without bound under a large volume of unique source IPs.
   */
  private ipFailureTracker = new Map<string, { count: number; windowStart: number }>();
  private readonly IP_FAILURE_WINDOW_MS = 5 * 60 * 1000; // 5 minutes

  constructor(store: PairStore, maxPairs = 2000, lockoutCount = 10, requireAtomic = false) {
    this.store = store;
    this.atomicStore = isAtomicPairStore(store) ? store : undefined;
    if (requireAtomic && !this.atomicStore) {
      throw new Error('AtomicPairStore is required for a production PairRegistry');
    }
    this.maxPairs = maxPairs;
    this.lockoutCount = lockoutCount;
  }

  /**
   * REG-02: Evict ipFailureTracker entries whose window has expired.
   * Called at the start of every recordActivity() so the map never grows
   * without bound. O(n) over unique (pairId:ip) pairs seen since last
   * successful auth for that pair — acceptable for a server-side registry
   * where pairs are long-lived and IPs recycle within the window.
   */
  private evictStaleIpEntries(): void {
    const now = Date.now();
    for (const [key, entry] of this.ipFailureTracker) {
      if (now - entry.windowStart > this.IP_FAILURE_WINDOW_MS) {
        this.ipFailureTracker.delete(key);
      }
    }
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
    const pairId = generateId('pair');
    const pair: StoredPair = {
      id: pairId,
      ...pending.registration,
      status: 'active',
      created: Date.now(),
      lastActive: null,
      requests: 0,
      failedSigs: 0,
      // Layer 8: Preserve kind and canaryClass from registration
      kind:        pending.registration.kind ?? 'legitimate',
      canaryClass: pending.registration.canaryClass,
    };
    if (this.atomicStore) {
      const approved = await this.atomicStore.approvePending(token, pending, pair, this.maxPairs);
      if (!approved) throw new Error(`Pending approval changed or was already consumed: ${token}`);
    } else {
      // Compatibility path for legacy, single-writer stores. Production
      // callers should construct PairRegistry with requireAtomic=true.
      await this.store.deletePending(token);
      await this.store.set(pair);
    }
    return pairId;
  }

  /**
   * Layer 8: Register a Ghost Pair (canary token).
   *
   * A Ghost Pair is a fully functional BPC pair whose credentials are
   * intentionally planted in high-risk locations to catch different attacker classes.
   * Three canaryClass values correspond to three distinct leak surfaces:
   *
   *   'env_file':       Plant in .env.example or sample config files.
   *                     Catches developers who copy sample configs without rotating,
   *                     and supply-chain attackers who scrape public repositories.
   *
   *   'docs':           Use as a fake example pairId in SDK documentation.
   *                     Catches attackers who read your docs and try example credentials.
   *
   *   'registry_exfil': Provision as a real pair but never use in production traffic.
   *                     Catches attackers who exfiltrated the database or obtained
   *                     the registry via the BPC-04 enumeration vector.
   *
   * When triggered, the middleware:
   *   1. Returns a hard authorization denial carrying shadow metadata
   *   2. Logs a CRITICAL severity audit event with full forensic detail
   *   3. Auto-routes the attacker's source IP to Shadow Mode
   *   4. A separate response layer may return synthetic data without granting access
   *
   * @param registration Standard PairRegistration (kind is forced to 'ghost')
   * @param canaryClass  Which leak surface this canary covers
   * @returns The ghost pair ID — plant this in your bait environment
   */
  async registerGhostPair(
    registration: Omit<PairRegistration, 'kind' | 'canaryClass'>,
    canaryClass: import('./types.js').CanaryClass = 'registry_exfil',
  ): Promise<string> {
    return this.registerDirect({ ...registration, kind: 'ghost', canaryClass });
  }

  /**
   * Layer 8: Register all three Ghost Pair leak surfaces at once.
   * Returns an object with the three pair IDs keyed by canaryClass.
   * Plant each ID in its corresponding bait environment.
   */
  async registerAllGhostPairs(
    baseRegistration: Omit<PairRegistration, 'kind' | 'canaryClass' | 'name'>,
    pubJwkByClass: {
      env_file:       JsonWebKey;
      docs:           JsonWebKey;
      registry_exfil: JsonWebKey;
    },
    secretHashByClass: {
      env_file:       string;
      docs:           string;
      registry_exfil: string;
    },
  ): Promise<{ env_file: string; docs: string; registry_exfil: string }> {
    const [envId, docsId, regId] = await Promise.all([
      this.registerGhostPair(
        { ...baseRegistration, name: 'ghost-env-file', pubJwk: pubJwkByClass.env_file, secretHash: secretHashByClass.env_file },
        'env_file',
      ),
      this.registerGhostPair(
        { ...baseRegistration, name: 'ghost-docs', pubJwk: pubJwkByClass.docs, secretHash: secretHashByClass.docs },
        'docs',
      ),
      this.registerGhostPair(
        { ...baseRegistration, name: 'ghost-registry-exfil', pubJwk: pubJwkByClass.registry_exfil, secretHash: secretHashByClass.registry_exfil },
        'registry_exfil',
      ),
    ]);
    return { env_file: envId, docs: docsId, registry_exfil: regId };
  }

  async registerDirect(registration: PairRegistration): Promise<string> {
    const token = await this.requestPairing(registration);
    return this.approvePairing(token);
  }

  async get(pairId: string): Promise<StoredPair | undefined> {
    return this.store.get(pairId);
  }

  async revoke(pairId: string): Promise<void> {
    if (this.atomicStore) {
      await this.atomicStore.atomicMutate(pairId, (current) => ({ ...current, status: 'revoked' }));
      return;
    }
    const pair = await this.store.get(pairId);
    if (pair) await this.store.set({ ...pair, status: 'revoked' });
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

  /**
   * Record authentication activity for a pair.
   *
   * BPC-09 FIX: IP-aware failure tracking. A pair is only locked when the
   * SAME IP accumulates >= lockoutCount failures within IP_FAILURE_WINDOW_MS.
   *
   * BPC-10 FIX: Cumulative failure decay (slow-drip evasion protection).
   * Failures are tracked with a half-life decay: each window, the cumulative
   * score is halved before new failures are added. This means an attacker
   * who sends 9 failures/window will accumulate: 9 → 13.5 → 15.75 → ...
   * eventually crossing the lockout threshold. They cannot probe indefinitely
   * by staying just below the per-window limit.
   *
   * REG-02: Stale ipFailureTracker entries are lazily evicted at the start
   * of every call to prevent unbounded memory growth.
   *
   * On success: resets all failure counters and clears all IP failure entries.
   */
  async recordActivity(pairId: string, success: boolean, ip?: string): Promise<void> {
    // REG-02: Evict stale entries before doing anything else.
    this.evictStaleIpEntries();
    if (success) {
      await this.claimSuccessfulUse(pairId);
      return;
    }

    const now = Date.now();
    let ipFailures: number | undefined;
    if (ip) {
      const ipKey = `${pairId}:${ip}`;
      const tracker = this.ipFailureTracker.get(ipKey);
      if (!tracker || now - tracker.windowStart > this.IP_FAILURE_WINDOW_MS) {
        this.ipFailureTracker.set(ipKey, { count: 1, windowStart: now });
      } else {
        tracker.count++;
      }
      ipFailures = this.ipFailureTracker.get(ipKey)!.count;
    }

    const apply = (source: Readonly<StoredPair>): StoredPair => {
      const pair = structuredClone(source) as StoredPair;
      if (ipFailures !== undefined) {
        pair.failedSigs = ipFailures;
        // BPC-10: Apply cumulative decay for slow-drip detection
        this._applyCumulativeDecay(pair, now);
        if (ipFailures >= this.lockoutCount && pair.status === 'active') {
          pair.status = 'locked';
        }
        // Also check cumulative threshold (catches slow-drip across windows)
        if ((pair.cumulativeFailures ?? 0) >= this.lockoutCount * 2 && pair.status === 'active') {
          pair.status = 'locked';
        }
      } else {
        // No IP provided — fallback to global counter with cumulative decay
        pair.failedSigs++;
        // BPC-10: Apply cumulative decay for slow-drip detection
        this._applyCumulativeDecay(pair, now);
        if (pair.failedSigs >= this.lockoutCount && pair.status === 'active') {
          pair.status = 'locked';
        }
        // Also check cumulative threshold
        if ((pair.cumulativeFailures ?? 0) >= this.lockoutCount * 2 && pair.status === 'active') {
          pair.status = 'locked';
        }
      }
      return pair;
    };
    if (this.atomicStore) {
      await this.atomicStore.atomicMutate(pairId, apply);
      return;
    }
    const pair = await this.store.get(pairId);
    if (pair) await this.store.set(apply(pair));
  }

  /** Persist expiry before returning an expiry denial. */
  async markExpired(pairId: string, now = Date.now()): Promise<boolean> {
    if (this.atomicStore) {
      return this.atomicStore.expireIfElapsed(pairId, now);
    }
    const pair = await this.store.get(pairId);
    if (pair?.status !== 'active' || pair.expiresAt === undefined || pair.expiresAt >= now) return false;
    await this.store.set({ ...pair, status: 'expired' });
    return true;
  }

  async markUsageExpired(pairId: string): Promise<boolean> {
    if (this.atomicStore) return this.atomicStore.expireIfUsageExhausted(pairId);
    const pair = await this.store.get(pairId);
    if (pair?.status !== 'active' || !pair.maxRequests || pair.maxRequests <= 0 || pair.requests < pair.maxRequests) return false;
    await this.store.set({ ...pair, status: 'expired' });
    return true;
  }

  /** Idempotently persist a threshold lock before returning a lock denial. */
  async ensureLocked(pairId: string, minimumFailures: number): Promise<boolean> {
    if (this.atomicStore) {
      return this.atomicStore.lockIfFailureThreshold(pairId, minimumFailures);
    }
    const pair = await this.store.get(pairId);
    if (pair?.status !== 'active' || pair.failedSigs < minimumFailures) return false;
    await this.store.set({ ...pair, status: 'locked' });
    return true;
  }

  /**
   * Atomically claim one successful authorization use. A false result means
   * the usage cap was already exhausted by a concurrent request.
   */
  async claimSuccessfulUse(pairId: string): Promise<boolean> {
    if (this.atomicStore) {
      const claimed = await this.atomicStore.claimSuccessfulUse(pairId, Date.now());
      if (claimed) {
        for (const key of this.ipFailureTracker.keys()) {
          if (key.startsWith(`${pairId}:`)) this.ipFailureTracker.delete(key);
        }
      }
      return claimed;
    }
    let claimed = false;
    const claim = (source: Readonly<StoredPair>): StoredPair => {
      const pair = structuredClone(source) as StoredPair;
      if (pair.status !== 'active') return pair;
      if (pair.maxRequests && pair.maxRequests > 0 && pair.requests >= pair.maxRequests) {
        pair.status = 'expired';
        return pair;
      }
      claimed = true;
      pair.requests++;
      pair.lastActive = Date.now();
      pair.failedSigs = 0;
      pair.cumulativeFailures = 0;
      pair.firstFailureAt = null;
      if (pair.maxRequests && pair.maxRequests > 0 && pair.requests >= pair.maxRequests) {
        pair.status = 'expired';
      }
      return pair;
    };
    const pair = await this.store.get(pairId);
    if (pair) await this.store.set(claim(pair));
    if (claimed) {
      for (const key of this.ipFailureTracker.keys()) {
        if (key.startsWith(`${pairId}:`)) this.ipFailureTracker.delete(key);
      }
    }
    return claimed;
  }

  /**
   * BPC-10: Apply half-life decay to cumulative failure score.
   * Called on every failure. Decays the cumulative score by half for each
   * full window that has elapsed since the first failure, then increments by 1.
   */
  private _applyCumulativeDecay(pair: import('./types.js').StoredPair, now = Date.now()): void {
    const firstFailure = pair.firstFailureAt ?? now;
    const windowsElapsed = Math.floor((now - firstFailure) / this.IP_FAILURE_WINDOW_MS);
    let cumulative = pair.cumulativeFailures ?? 0;
    // Decay: halve for each elapsed window (minimum 0)
    if (windowsElapsed > 0) {
      cumulative = cumulative / Math.pow(2, windowsElapsed);
    }
    // Add this failure
    cumulative += 1;
    pair.cumulativeFailures = cumulative;
    // Update firstFailureAt: reset to now if we decayed (new cycle), else keep original
    pair.firstFailureAt = windowsElapsed > 0 ? now : firstFailure;
  }

  async unlock(pairId: string): Promise<void> {
    if (this.atomicStore) {
      await this.atomicStore.atomicMutate(pairId, (pair) => pair.status === 'locked'
        ? { ...pair, status: 'active', failedSigs: 0 }
        : { ...pair });
      return;
    }
    const pair = await this.store.get(pairId);
    if (pair?.status === 'locked') await this.store.set({ ...pair, status: 'active', failedSigs: 0 });
  }

  /**
   * Update mutable lifecycle fields on an existing pair.
   *
   * Only the fields present in `updates` are changed. Fields not included
   * are left untouched. Immutable fields (id, secretHash, pubJwk, created,
   * requests, failedSigs) cannot be changed via this method.
   *
   * Allowed updates:
   *   - scope:       Change the permission level (read / read-write / admin)
   *   - expiresAt:   Set or clear the expiry timestamp (ms since epoch, or undefined)
   *   - maxRequests: Set or clear the usage cap (positive integer, or undefined)
   *   - name:        Rename the pair label
   *
   * Returns a safe copy of the updated pair (REG-01 fix: not the live
   * mutable reference). Returns undefined if the pairId does not exist.
   */
  async updatePair(
    pairId: string,
    updates: Partial<Pick<StoredPair, 'scope' | 'expiresAt' | 'maxRequests' | 'name'>>,
  ): Promise<StoredPair | undefined> {
    const apply = (source: Readonly<StoredPair>): StoredPair => {
      const pair = structuredClone(source) as StoredPair;
      if (updates.scope !== undefined) {
        if (!ALLOWED_SCOPES.has(updates.scope)) {
          throw new Error(`Invalid scope: ${updates.scope}. Must be one of: ${[...ALLOWED_SCOPES].join(', ')}`);
        }
        pair.scope = updates.scope;
      }
      if ('expiresAt' in updates) pair.expiresAt = updates.expiresAt;
      if ('maxRequests' in updates) pair.maxRequests = updates.maxRequests;
      if (updates.name !== undefined) pair.name = updates.name;
      return pair;
    };
    if (this.atomicStore) return this.atomicStore.atomicMutate(pairId, apply);
    const pair = await this.store.get(pairId);
    if (!pair) return undefined;
    const updated = apply(pair);
    await this.store.set(updated);
    return structuredClone(updated);
  }
}
