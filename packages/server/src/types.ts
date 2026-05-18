/**
 * @bpc/server — Server-side types for BPC Protocol v1.0
 */

export interface StoredPair {
  id: string;
  name: string;
  scope: 'read' | 'read-write' | 'admin';
  mode: 'development' | 'production';
  secretHash: string;       // SHA-256(bpc:+secret) base64url — stored at pairing
  pubJwk: JsonWebKey;       // Registered public key
  status: 'active' | 'locked' | 'expired' | 'rotated' | 'revoked';
  created: number;
  lastActive: number | null;
  requests: number;
  failedSigs: number;
  /**
   * BPC-10 FIX — Slow-drip evasion protection.
   * Cumulative failure score with half-life decay per IP_FAILURE_WINDOW_MS.
   * Failures never reset to zero on window expiry — they decay by half.
   * An attacker sending 9 failures/window accumulates: 9 → 13.5 → 15.75...
   * eventually crossing the lockout threshold, closing the slow-drip gap.
   */
  cumulativeFailures?: number;
  /** Timestamp of the first failure in the current decay cycle. */
  firstFailureAt?: number | null;
  expiresAt?: number;
}

export interface PairRegistration {
  name: string;
  scope: StoredPair['scope'];
  mode: StoredPair['mode'];
  secretHash: string;
  pubJwk: JsonWebKey;
  expiresAt?: number;
}

export interface BPCVerifyResult {
  ok: boolean;
  pairId?: string;
  pair?: StoredPair;
  error?: string;
  rateLimitRemaining?: number;
}

export interface AnomalyCounters {
  unknownPairProbes: number;
  sigFailures: number;
  replayAttempts: number;
  expiredTimestamps: number;
  totalRequests: number;
  deniedRequests: number;
}
