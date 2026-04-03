/**
 * @bpc/server — Server-side types for BPC Protocol v0.1.0
 *
 * HMAC verification note (v0.1.0):
 * The server stores secretHash (SHA-256 of "bpc:" + secret, base64url) at pairing time.
 * The secret_hmac field in the canonical payload is covered by the ECDSA signature —
 * if the signature is valid, the secret_hmac was computed by the legitimate pair holder.
 * Independent server-side HMAC recomputation requires HKDF-derived key storage,
 * deferred to v0.2.0. See spec/bpc-spec-v1.md section 6.
 */

export interface StoredPair {
  id: string;
  name: string;
  scope: 'read' | 'read-write' | 'full';
  mode: 'development' | 'production';
  secretHash: string;       // SHA-256(bpc:+secret) base64url — stored at pairing
  pubJwk: JsonWebKey;       // Registered public key
  status: 'active' | 'revoked';
  created: number;
  lastActive: number | null;
  requests: number;
  failedSigs: number;
}

export interface PairRegistration {
  name: string;
  scope: StoredPair['scope'];
  mode: StoredPair['mode'];
  secretHash: string;
  pubJwk: JsonWebKey;
}

export interface BPCVerifyResult {
  ok: boolean;
  pairId?: string;
  pair?: StoredPair;
  error?: string;
}

export interface AnomalyCounters {
  unknownPairProbes: number;
  sigFailures: number;
  replayAttempts: number;
  expiredTimestamps: number;
  totalRequests: number;
  deniedRequests: number;
}
