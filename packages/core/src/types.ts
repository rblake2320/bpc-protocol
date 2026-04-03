export interface BPCKeypair {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  pubJwk: JsonWebKey;
  fingerprint: string; // first 20 chars of base64url(SHA-256(pubJwk JSON))
}

export interface BPCPair {
  id: string;
  name: string;
  scope: 'read' | 'read-write' | 'full';
  mode: 'development' | 'production';
  secretHash: string;       // SHA-256(bpc: + secret), base64url
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  fingerprint: string;
  status: 'active' | 'revoked';
  created: number;          // Unix ms
  lastActive: number | null;
  requests: number;
  failedSigs: number;
}

export interface BPCCanonicalPayload {
  body_hash: string;
  method: string;
  nonce: string;
  pair_id: string;
  path: string;
  secret_hmac: string;
  timestamp: number;
}

export interface BPCSignedRequest {
  payload: BPCCanonicalPayload;
  signature: string;        // base64url ECDSA-SHA256 signature
  pairId: string;
}

export interface BPCConfig {
  maxPairs: number;
  sigWindowMs: number;      // timestamp validity window in milliseconds
  alertThreshold: number;
  lockoutCount: number;
}

export const DEFAULT_CONFIG: BPCConfig = {
  maxPairs: 2000,
  sigWindowMs: 60_000,
  alertThreshold: 5,
  lockoutCount: 10,
};
