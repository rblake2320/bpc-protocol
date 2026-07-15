/**
 * @bpc/server — Server-side types for BPC Protocol v1.0
 *
 * Layer 8: Active Defense types added.
 * See LAYER8_SPEC.md for full design rationale.
 */

// ─────────────────────────────────────────────────────────────────────────────
// Layer 8: Ghost Pair (Canary Token) types
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Identifies the leak surface of a Ghost Pair (canary token).
 * Each class catches a different attacker profile:
 *
 * - 'env_file':        Credentials planted in .env.example or sample config files.
 *                      Catches developers who copy sample configs without rotating,
 *                      and supply-chain attackers who scrape public repositories.
 *
 * - 'docs':            Fake example pairId used in SDK documentation that is
 *                      actually live in the registry. Catches attackers who read
 *                      your docs and attempt to authenticate with example credentials.
 *
 * - 'registry_exfil':  A real pair provisioned but never used in production traffic.
 *                      Catches attackers who exfiltrated the database or obtained
 *                      the registry via the BPC-04 enumeration vector.
 */
export type CanaryClass = 'env_file' | 'docs' | 'registry_exfil';

/** 'legitimate' = real production pair. 'ghost' = canary token. */
export type PairKind = 'legitimate' | 'ghost';

// ─────────────────────────────────────────────────────────────────────────────
// Layer 8: Anomaly Engine State Machine
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Anomaly engine verdict states.
 *
 * State machine:
 *   clean → suspicious → shadow
 *                ↓
 *             tarpit
 *
 * 'shadow' is a FIRST-CLASS STATE, not a middleware branch.
 * It is scoped to (sourceIP + pairId), NOT the pair globally.
 * A legitimate user on a different IP hitting the same pairId gets real auth.
 *
 * 'shadow' persists for 24 hours minimum. Reset requires explicit operator action.
 * It is never reset by timeout alone.
 */
export type AnomalyVerdict = 'clean' | 'suspicious' | 'shadow' | 'attack';

/**
 * Tarpit delay configuration keyed by anomaly verdict.
 * Delays are applied per source IP BEFORE the response is sent,
 * occupying the attacker's connection pool.
 *
 * clean:      0ms   (no delay)
 * suspicious: 500ms (graduated response — slows probing)
 * shadow:     2000ms (deep tarpit — attacker believes they're in a slow network)
 * attack:     immediate 429 (scanner blocking)
 */
export const TARPIT_DELAY_MS: Record<AnomalyVerdict, number> = {
  clean:      0,
  suspicious: 500,
  shadow:     2000,
  attack:     0,   // attack verdict returns 429 immediately — no delay needed
};

// ─────────────────────────────────────────────────────────────────────────────
// Core pair storage types
// ─────────────────────────────────────────────────────────────────────────────

export interface StoredPair {
  id: string;
  name: string;
  scope: 'read' | 'read-write' | 'admin';
  mode: 'development' | 'production';
  secretHash: string;       // HKDF-derived request HMAC key, base64url
  pubJwk: JsonWebKey;       // Registered public key
  status: 'active' | 'locked' | 'expired' | 'rotated' | 'revoked';
  created: number;
  lastActive: number | null;
  requests: number;
  failedSigs: number;
  /**
   * BPC-10 FIX — Slow-drip evasion protection.
   * Cumulative failure score with half-life decay per IP_FAILURE_WINDOW_MS.
   */
  cumulativeFailures?: number;
  /** Timestamp of the first failure in the current decay cycle. */
  firstFailureAt?: number | null;
  expiresAt?: number;
  /**
   * Optional hard cap on the total number of successful requests this pair
   * may serve. Once pair.requests reaches maxRequests the pair is
   * automatically transitioned to 'expired' and all subsequent requests
   * are denied with error code 'pair_usage_cap_exceeded'.
   *
   * Omit (or set to 0) for unlimited usage.
   */
  maxRequests?: number;
  /**
   * Layer 8: Ghost Pair (canary token) flag.
   * Default: 'legitimate'. Set to 'ghost' via registerGhostPair().
   */
  kind?: PairKind;
  /**
   * Layer 8: Canary class — identifies which leak surface this ghost pair covers.
   * Only meaningful when kind === 'ghost'.
   */
  canaryClass?: CanaryClass;
}

export interface PairRegistration {
  name: string;
  scope: StoredPair['scope'];
  mode: StoredPair['mode'];
  secretHash: string;
  pubJwk: JsonWebKey;
  expiresAt?: number;
  /** Optional hard cap on total successful requests. 0 or omitted = unlimited. */
  maxRequests?: number;
  /** Layer 8: Pair kind. Default: 'legitimate'. */
  kind?: PairKind;
  /** Layer 8: Canary class (required when kind === 'ghost'). */
  canaryClass?: CanaryClass;
}

export interface BPCVerifyResult {
  ok: boolean;
  pairId?: string;
  pair?: StoredPair;
  error?: string;
  rateLimitRemaining?: number;
  /**
   * Layer 8: Shadow Mode indicator.
   * When true, the request was classified for deception handling. It remains
   * an authorization failure (`ok` is false); any synthetic response belongs
   * outside the authorization result.
   * NEVER expose this field to the client — it is server-internal only.
   */
  shadow?: boolean;
  /**
   * Layer 8: Ghost Pair breach alert.
   * When true, a canary credential was used — confirmed breach.
   * Includes the canaryClass so the SOC knows how the attacker found it.
   * NEVER expose this field to the client.
   */
  ghostAlert?: boolean;
  /** Layer 8: The canary class of the ghost pair that was triggered. */
  canaryClass?: CanaryClass;
  /**
   * Layer 8: Tarpit delay applied (ms).
   * The middleware applied this delay before sending the response.
   * Logged for forensic analysis.
   */
  tarpitDelayMs?: number;
}

export interface AnomalyCounters {
  unknownPairProbes: number;
  sigFailures: number;
  replayAttempts: number;
  expiredTimestamps: number;
  totalRequests: number;
  deniedRequests: number;
}
