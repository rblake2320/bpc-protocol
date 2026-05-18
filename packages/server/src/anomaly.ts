/**
 * BPC Anomaly Engine — Layer 8 Active Defense
 *
 * State machine (per source IP + pairId combination):
 *
 *   clean → suspicious → shadow
 *                ↓
 *             tarpit
 *
 * CRITICAL DESIGN CONSTRAINT:
 * Shadow state is scoped to (sourceIP + pairId), NOT the pair globally.
 * A legitimate user on a different IP hitting the same pairId gets real auth.
 * Applying shadow state globally would recreate the lockout DoS with extra steps.
 *
 * Shadow state persists for 24 hours minimum.
 * Reset requires explicit operator action — never resets on timeout alone.
 *
 * Tarpit delays are applied per source IP BEFORE the response is sent,
 * occupying the attacker's connection pool:
 *   clean:      0ms
 *   suspicious: 500ms
 *   shadow:     2000ms
 *   attack:     immediate 429 (no delay)
 */

import type { AnomalyStore } from './store.js';
import type { AnomalyCounters, AnomalyVerdict } from './types.js';
import { TARPIT_DELAY_MS } from './types.js';

const WINDOW_MS = 3_600_000;       // 1 hour rolling window for counters
const SHADOW_PERSIST_MS = 86_400_000; // 24 hours — shadow state minimum persistence

// Thresholds for state transitions (per sourceIP+pairId)
const SUSPICIOUS_SIG_FAIL_THRESHOLD = 3;   // 3+ sig failures → suspicious
const SHADOW_SIG_FAIL_THRESHOLD     = 7;   // 7+ sig failures → shadow

/**
 * Shadow state record — tracks which (sourceIP + pairId) combinations
 * are currently in shadow mode and when they entered.
 */
interface ShadowRecord {
  enteredAt: number;
  sourceIp: string;
  pairId: string;
  reason: string;
}

export class AnomalyEngine {
  /**
   * Shadow state store: key = `${pairId}:${sourceIp}`, value = ShadowRecord.
   * This is in-memory for single-process deployments.
   * For distributed deployments, replace with Redis HSET with TTL.
   */
  private shadowState = new Map<string, ShadowRecord>();

  /**
   * Tarpit state: key = sourceIp, value = { verdict, since }.
   * Tracks which IPs are currently in tarpit mode.
   */
  private tarpitState = new Map<string, { verdict: AnomalyVerdict; since: number }>();

  constructor(private store: AnomalyStore) {}

  // ─────────────────────────────────────────────────────────────────────────
  // Standard counter recording (unchanged from v1)
  // ─────────────────────────────────────────────────────────────────────────

  async recordRequest(pairId?: string): Promise<void> {
    await this.store.increment('global:total', WINDOW_MS);
    if (pairId) await this.store.increment(`pair:${pairId}:total`, WINDOW_MS);
  }

  async recordDenied(pairId?: string): Promise<void> {
    await this.store.increment('global:denied', WINDOW_MS);
    if (pairId) await this.store.increment(`pair:${pairId}:denied`, WINDOW_MS);
  }

  async recordUnknownPair(): Promise<void> {
    await this.store.increment('global:unknown_pair', WINDOW_MS);
  }

  async recordSigFailure(pairId?: string): Promise<void> {
    await this.store.increment('global:sig_fail', WINDOW_MS);
    if (pairId) await this.store.increment(`pair:${pairId}:sig_fail`, WINDOW_MS);
  }

  async recordReplay(pairId?: string): Promise<void> {
    await this.store.increment('global:replay', WINDOW_MS);
    if (pairId) await this.store.increment(`pair:${pairId}:replay`, WINDOW_MS);
  }

  async recordExpiredTimestamp(pairId?: string): Promise<void> {
    await this.store.increment('global:expired_ts', WINDOW_MS);
    if (pairId) await this.store.increment(`pair:${pairId}:expired_ts`, WINDOW_MS);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Layer 8: Shadow State Machine
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Get the current anomaly verdict for a (sourceIP + pairId) combination.
   *
   * This is the core of the Layer 8 state machine. It evaluates:
   * 1. Is this (IP + pairId) already in shadow state? → return 'shadow'
   * 2. How many sig failures has this IP accumulated for this pair? → suspicious/shadow
   * 3. What is the global threat score? → attack
   *
   * SCOPING: The verdict is per (sourceIP + pairId). A different IP hitting
   * the same pairId gets an independent verdict.
   */
  async getVerdict(pairId: string, sourceIp: string): Promise<AnomalyVerdict> {
    const shadowKey = `${pairId}:${sourceIp}`;

    // Check shadow state first (persists 24h, operator-reset only)
    const shadow = this.shadowState.get(shadowKey);
    if (shadow) {
      // Shadow state never expires on its own — only operator reset clears it
      return 'shadow';
    }

    // Check per-IP sig failure count for this pair
    const ipPairSigFails = await this.store.get(`ip:${sourceIp}:pair:${pairId}:sig_fail`);

    if (ipPairSigFails >= SHADOW_SIG_FAIL_THRESHOLD) {
      // Automatically promote to shadow state
      await this.enterShadowState(pairId, sourceIp, `sig_fail_threshold:${ipPairSigFails}`);
      return 'shadow';
    }

    if (ipPairSigFails >= SUSPICIOUS_SIG_FAIL_THRESHOLD) {
      return 'suspicious';
    }

    // Check global threat score for 'attack' verdict
    const score = await this.threatScore();
    if (score >= 70) return 'attack';

    return 'clean';
  }

  /**
   * Record a signature failure scoped to (sourceIP + pairId).
   * This feeds the per-IP-per-pair counter that drives shadow state transitions.
   */
  async recordSigFailureForIp(pairId: string, sourceIp: string): Promise<void> {
    await this.store.increment(`ip:${sourceIp}:pair:${pairId}:sig_fail`, WINDOW_MS);
    // Also record globally
    await this.recordSigFailure(pairId);
  }

  /**
   * Enter shadow state for a (sourceIP + pairId) combination.
   * This is a first-class state transition — not a middleware branch.
   *
   * Shadow state:
   * - Persists for 24 hours minimum
   * - Resets only on explicit operator action (clearShadowState)
   * - All requests return { ok: true, shadow: true } with fake session token
   * - Tarpit delay of 2000ms applied before response
   */
  async enterShadowState(pairId: string, sourceIp: string, reason: string): Promise<void> {
    const shadowKey = `${pairId}:${sourceIp}`;
    this.shadowState.set(shadowKey, {
      enteredAt: Date.now(),
      sourceIp,
      pairId,
      reason,
    });
    // Also put the IP in tarpit state at shadow level
    this.tarpitState.set(sourceIp, { verdict: 'shadow', since: Date.now() });
  }

  /**
   * Operator-only: Clear shadow state for a (sourceIP + pairId) combination.
   * This is the ONLY way to exit shadow state — no automatic timeout.
   */
  clearShadowState(pairId: string, sourceIp: string): void {
    const shadowKey = `${pairId}:${sourceIp}`;
    this.shadowState.delete(shadowKey);
    this.tarpitState.delete(sourceIp);
  }

  /**
   * Check if a (sourceIP + pairId) combination is in shadow state.
   * Used by middleware to decide whether to return deceptive success.
   */
  isInShadowState(pairId: string, sourceIp: string): boolean {
    return this.shadowState.has(`${pairId}:${sourceIp}`);
  }

  /**
   * Get all active shadow state records (for operator dashboard / SOC monitoring).
   */
  listShadowState(): ShadowRecord[] {
    return Array.from(this.shadowState.values());
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Layer 8: Cryptographic Tarpit
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Apply tarpit delay for a source IP based on its current anomaly verdict.
   * The delay is applied BEFORE the response is sent, occupying the attacker's
   * connection pool. Applied per source IP, not per pairId.
   *
   * Returns the delay applied in milliseconds (for logging/forensics).
   */
  async applyTarpit(sourceIp: string, verdict: AnomalyVerdict): Promise<number> {
    const delayMs = TARPIT_DELAY_MS[verdict] ?? 0;
    if (delayMs > 0) {
      // Update tarpit state for this IP
      this.tarpitState.set(sourceIp, { verdict, since: Date.now() });
      // Apply the delay — occupies the attacker's connection slot
      await new Promise<void>(resolve => setTimeout(resolve, delayMs));
    }
    return delayMs;
  }

  /**
   * Get the current tarpit state for a source IP.
   */
  getTarpitState(sourceIp: string): { verdict: AnomalyVerdict; since: number } | undefined {
    return this.tarpitState.get(sourceIp);
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Standard scoring and counters (unchanged from v1)
  // ─────────────────────────────────────────────────────────────────────────

  async threatScore(): Promise<number> {
    const total = await this.store.get('global:total');
    if (total === 0) return 0;
    const unknownPair = await this.store.get('global:unknown_pair');
    const sigFail = await this.store.get('global:sig_fail');
    const replay = await this.store.get('global:replay');
    const expiredTs = await this.store.get('global:expired_ts');

    const unknownRate = Math.min(unknownPair / total, 1);
    const sigRate = Math.min(sigFail / total, 1);
    const replayRate = Math.min(replay / total, 1);
    const expiredRate = Math.min(expiredTs / total, 1);
    return Math.round((unknownRate * 30 + sigRate * 30 + replayRate * 20 + expiredRate * 20) * 100);
  }

  async counters(): Promise<AnomalyCounters> {
    return {
      unknownPairProbes: await this.store.get('global:unknown_pair'),
      sigFailures: await this.store.get('global:sig_fail'),
      replayAttempts: await this.store.get('global:replay'),
      expiredTimestamps: await this.store.get('global:expired_ts'),
      totalRequests: await this.store.get('global:total'),
      deniedRequests: await this.store.get('global:denied'),
    };
  }

  async pairCounters(pairId: string): Promise<{ total: number; denied: number; sigFail: number; replay: number }> {
    return {
      total: await this.store.get(`pair:${pairId}:total`),
      denied: await this.store.get(`pair:${pairId}:denied`),
      sigFail: await this.store.get(`pair:${pairId}:sig_fail`),
      replay: await this.store.get(`pair:${pairId}:replay`),
    };
  }
}
