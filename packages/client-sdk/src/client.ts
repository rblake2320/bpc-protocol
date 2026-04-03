import {
  signPayload, hmacDerive,
  generateNonce, b64url, canonicalize
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
      bodyHash = 'sha256:' + b64url(digest).substring(0, 32);
    } else {
      bodyHash = EMPTY_BODY_HASH;
    }

    const secretHmac = await hmacDerive(this.config.secret, nonce + timestamp);

    const payload = {
      body_hash: bodyHash,
      method,
      nonce,
      pair_id: this.config.pairId,
      path,
      secret_hmac: secretHmac,
      timestamp,
    };

    const signature = await signPayload(this.config.keypair.privateKey, payload);

    // Encode canonical payload as base64url for the header
    const canonical = canonicalize(payload);
    const signedData = b64url(new TextEncoder().encode(canonical).buffer as ArrayBuffer);

    return {
      'X-BPC-Pair-ID': this.config.pairId,
      'X-BPC-Signature': signature,
      'X-BPC-Signed-Data': signedData,
    };
  }

  /** Signed fetch — automatically adds BPC headers */
  async fetch(path: string, init: RequestInit = {}): Promise<Response> {
    const method = (init.method ?? 'GET').toUpperCase();
    const body = init.body ? JSON.parse(init.body as string) : undefined;
    const headers = await this.signRequest(method, path, body);
    return fetch(this.config.serverUrl + path, {
      ...init,
      method,
      headers: { ...Object.fromEntries(new Headers(init.headers as HeadersInit).entries()), ...headers },
    });
  }
}
