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
      const bodyBytes = await exactBodyBytes(body);
      const digest = await crypto.subtle.digest('SHA-256', bodyBytes);
      bodyHash = 'sha256:' + b64url(digest);
    } else {
      bodyHash = EMPTY_BODY_HASH;
    }

    // Derive the same domain-separated HKDF request key sent during pairing.
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
    const headers = await this.signRequest(method, path, init.body ?? undefined);
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
    // BPC-05: canonicalize() only accepts flat (scalar) payloads.
    // Serialize new_pub_jwk as a JSON string so it is a scalar field.
    const rotationPayload = {
      new_pub_jwk_json: JSON.stringify(newPubJwk),
      old_pair_id:      this.config.pairId,
      purpose:          'rotation' as const,
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

async function exactBodyBytes(body: unknown): Promise<ArrayBuffer> {
  if (typeof body === 'string') return copyBytes(new TextEncoder().encode(body));
  if (body instanceof ArrayBuffer) return body.slice(0);
  if (ArrayBuffer.isView(body)) {
    return copyBytes(new Uint8Array(body.buffer, body.byteOffset, body.byteLength));
  }
  if (typeof URLSearchParams !== 'undefined' && body instanceof URLSearchParams) {
    return copyBytes(new TextEncoder().encode(body.toString()));
  }
  if (typeof Blob !== 'undefined' && body instanceof Blob) {
    return body.arrayBuffer();
  }
  if (typeof FormData !== 'undefined' && body instanceof FormData) {
    throw new TypeError('BPCClient: FormData wire boundaries cannot be pre-hashed deterministically');
  }
  if (typeof ReadableStream !== 'undefined' && body instanceof ReadableStream) {
    throw new TypeError('BPCClient: streaming request bodies require an application-supplied digest adapter');
  }
  if (typeof body === 'object') {
    return copyBytes(new TextEncoder().encode(JSON.stringify(body)));
  }
  throw new TypeError(`BPCClient: unsupported request body type ${typeof body}`);
}

function copyBytes(view: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(view.byteLength);
  copy.set(view);
  return copy.buffer;
}
