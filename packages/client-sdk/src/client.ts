import {
  signPayload, hmacDerive, hashSecret,
  generateNonce, b64url, canonicalize,
  BPC_PROTOCOL_VERSION,
} from '@bpc/core';
import type { BPCKeypair } from '@bpc/core';

export interface BPCClientConfig {
  serverUrl: string;
  pairId: string;
  keypair: BPCKeypair;
  secret: string;        // User-chosen secret — never logged, never sent in clear
  scope?: string;
}

export interface SignedHeaders {
  'X-BPC-Pair-ID': string;
  'X-BPC-Signature': string;
  'X-BPC-Signed-Data': string;  // base64url of canonical payload JSON
  'X-BPC-Version': string;
}

// SHA-256 of empty string in base64url (precomputed, standard value)
const EMPTY_BODY_HASH = 'sha256:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU';

export class BPCClient {
  constructor(private config: BPCClientConfig) {}

  async signRequest(method: string, path: string, body?: unknown): Promise<SignedHeaders> {
    const nonce = generateNonce();
    const timestamp = Date.now();

    let bodyHash: string;
    if (body != null) {
      const bodyBytes = new TextEncoder().encode(JSON.stringify(body));
      const digest = await crypto.subtle.digest('SHA-256', bodyBytes);
      bodyHash = 'sha256:' + b64url(digest);
    } else {
      bodyHash = EMPTY_BODY_HASH;
    }

    // Derive secretHash the same way the server does at pairing time:
    // server stores hashSecret(secret) = SHA256('bpc:' + secret) — HMAC key must match
    const secretHash = await hashSecret(this.config.secret);
    const secretHmac = await hmacDerive(secretHash, nonce + timestamp);

    const payload = {
      body_hash: bodyHash,
      method,
      nonce,
      pair_id: this.config.pairId,
      path,
      secret_hmac: secretHmac,
      timestamp,
      version: BPC_PROTOCOL_VERSION,
    };

    const signature = await signPayload(this.config.keypair.privateKey, payload);

    // Encode canonical payload as base64url for the header
    const canonical = canonicalize(payload);
    const signedData = b64url(new TextEncoder().encode(canonical).buffer as ArrayBuffer);

    return {
      'X-BPC-Pair-ID': this.config.pairId,
      'X-BPC-Signature': signature,
      'X-BPC-Signed-Data': signedData,
      'X-BPC-Version': BPC_PROTOCOL_VERSION,
    };
  }

  /** Signed fetch — automatically adds BPC headers */
  async fetch(path: string, init: RequestInit = {}): Promise<Response> {
    if (
      !this.config.serverUrl.startsWith('https://') &&
      !this.config.serverUrl.startsWith('http://localhost') &&
      !this.config.serverUrl.startsWith('http://127.0.0.1')
    ) {
      throw new Error(`BPCClient: serverUrl must use HTTPS in production. Got: ${this.config.serverUrl}`);
    }
    const method = (init.method ?? 'GET').toUpperCase();
    const body = init.body ? JSON.parse(init.body as string) : undefined;
    const headers = await this.signRequest(method, path, body);
    return fetch(this.config.serverUrl + path, {
      ...init,
      method,
      headers: { ...(init.headers ? Object.fromEntries(Object.entries(init.headers as Record<string, string>)) : {}), ...headers },
    });
  }

  /**
   * Request pair rotation — signs a rotation payload with the current key,
   * sends it to the server's rotation endpoint, and returns the new pair ID.
   */
  async rotate(newPubJwk: JsonWebKey, rotationEndpoint = '/bpc/rotate'): Promise<{ newPairId: string }> {
    const timestamp = Date.now();
    const rotationPayload = {
      old_pair_id: this.config.pairId,
      new_pub_jwk: newPubJwk,
      purpose: 'rotation' as const,
      timestamp,
    };

    const canonical = canonicalize(rotationPayload);
    const signedData = b64url(new TextEncoder().encode(canonical).buffer as ArrayBuffer);
    const signature = await signPayload(this.config.keypair.privateKey, rotationPayload as Record<string, unknown>);

    const res = await fetch(this.config.serverUrl + rotationEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-BPC-Version': BPC_PROTOCOL_VERSION },
      body: JSON.stringify({ oldPairId: this.config.pairId, newPubJwk, signature, signedData, timestamp }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: 'rotation_failed' })) as { error: string };
      throw new Error(`BPC rotation failed: ${err.error}`);
    }

    const body = await res.json() as { newPairId: string };
    return body;
  }
}
