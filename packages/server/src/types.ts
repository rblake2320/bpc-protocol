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
