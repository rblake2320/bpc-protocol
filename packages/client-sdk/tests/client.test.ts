import { describe, it, expect } from 'vitest';
import { BPCClient } from '../src/client.js';
import { BPC_PROTOCOL_VERSION, generateKeypair, b64urlDecode, hashSecret, hmacDerive } from '../../core/src/index.js';
import { prepareRegistration } from '../src/registration.js';
import type { BPCKeypair } from '../../core/src/index.js';

describe('@bpc/client-sdk -- BPCClient', () => {
  it('should include X-BPC-Version header in signed requests', async () => {
    const keypair = await generateKeypair();
    const client = new BPCClient({
      serverUrl: 'http://localhost:3100',
      pairId: 'pair_test',
      keypair,
      secret: 'TestSecret1!',
    });

    const headers = await client.signRequest('GET', '/api/test');
    expect(headers['X-BPC-Version']).toBe(BPC_PROTOCOL_VERSION);
    expect(headers['X-BPC-Version']).toBe('1.0');
  });

  it('should include version in signed payload', async () => {
    const keypair = await generateKeypair();
    const client = new BPCClient({
      serverUrl: 'http://localhost:3100',
      pairId: 'pair_test',
      keypair,
      secret: 'TestSecret1!',
    });

    const headers = await client.signRequest('GET', '/api/test');

    // Decode the signed data to inspect the payload
    const signedDataJson = new TextDecoder().decode(b64urlDecode(headers['X-BPC-Signed-Data']));
    const payload = JSON.parse(signedDataJson) as Record<string, unknown>;

    expect(payload['version']).toBe(BPC_PROTOCOL_VERSION);
  });

  it('should produce full body hash (not truncated)', async () => {
    const keypair = await generateKeypair();
    const client = new BPCClient({
      serverUrl: 'http://localhost:3100',
      pairId: 'pair_test',
      keypair,
      secret: 'TestSecret1!',
    });

    const headers = await client.signRequest('POST', '/api/data', { foo: 'bar' });
    const signedDataJson = new TextDecoder().decode(b64urlDecode(headers['X-BPC-Signed-Data']));
    const payload = JSON.parse(signedDataJson) as Record<string, unknown>;

    // body_hash should be 'sha256:' + full 43-char base64url, not truncated to 32
    const bodyHash = payload['body_hash'] as string;
    expect(bodyHash).toMatch(/^sha256:[A-Za-z0-9_-]{43}$/);
  });

  it('should derive secret_hmac from hashSecret(secret)', async () => {
    const keypair = await generateKeypair();
    const client = new BPCClient({
      serverUrl: 'http://localhost:3100',
      pairId: 'pair_test',
      keypair,
      secret: 'TestSecret1!',
    });

    const headers = await client.signRequest('GET', '/api/test');
    const signedDataJson = new TextDecoder().decode(b64urlDecode(headers['X-BPC-Signed-Data']));
    const payload = JSON.parse(signedDataJson) as Record<string, string>;

    const secretHash = await hashSecret('TestSecret1!');
    const expectedSecretHmac = await hmacDerive(secretHash, payload['nonce'] + payload['timestamp']);
    expect(payload['secret_hmac']).toBe(expectedSecretHmac);
  });

  it('should reject non-HTTPS URLs in production (not localhost)', async () => {
    const keypair = await generateKeypair();
    const client = new BPCClient({
      serverUrl: 'http://example.com',
      pairId: 'pair_test',
      keypair,
      secret: 'TestSecret1!',
    });

    await expect(client.fetch('/api/test')).rejects.toThrow('HTTPS');
  });

  it('should allow HTTP localhost URLs', async () => {
    const keypair = await generateKeypair();
    const client = new BPCClient({
      serverUrl: 'http://localhost:3100',
      pairId: 'pair_test',
      keypair,
      secret: 'TestSecret1!',
    });

    // Should not throw HTTPS error -- signRequest works fine on localhost
    const headers = await client.signRequest('GET', '/api/test');
    expect(headers['X-BPC-Pair-ID']).toBe('pair_test');
  });
  it('should include purpose=rotation in the signed rotation payload', async () => {
    const keypair = await generateKeypair();
    const client = new BPCClient({
      serverUrl: 'http://localhost:3100',
      pairId: 'pair_test',
      keypair,
      secret: 'TestSecret1!',
    });

    const nextKeypair = await generateKeypair();
    let capturedBody: string | undefined;

    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (_input: RequestInfo | URL, init?: RequestInit) => {
      capturedBody = init?.body as string | undefined;
      return new Response(JSON.stringify({ success: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }) as typeof fetch;

    try {
      await client.rotate(nextKeypair.pubJwk);
    } finally {
      globalThis.fetch = originalFetch;
    }

    expect(capturedBody).toBeDefined();
    const rotationRequest = JSON.parse(capturedBody ?? '{}') as { signedData: string };
    const signedDataJson = new TextDecoder().decode(b64urlDecode(rotationRequest.signedData));
    const payload = JSON.parse(signedDataJson) as Record<string, unknown>;

    expect(payload['purpose']).toBe('rotation');
    // IL4-7 / BPC-05: new_pub_jwk is now serialized as a JSON string field.
    expect(typeof payload['new_pub_jwk_json']).toBe('string');
    const parsedJwk = JSON.parse(payload['new_pub_jwk_json'] as string) as JsonWebKey;
    expect(parsedJwk.kty).toBe('EC');
  });
});

describe('prepareRegistration', () => {
  it('should produce a keypair and a registration request with secretHash', async () => {
    const { keypair, request } = await prepareRegistration('test-device', 'my-secret', 'read', 'development');

    expect(keypair.privateKey).toBeDefined();
    expect(keypair.publicKey).toBeDefined();
    expect(keypair.pubJwk).toBeDefined();
    expect(keypair.fingerprint).toBeDefined();
    expect(keypair.fingerprint.length).toBe(20);

    expect(request.name).toBe('test-device');
    expect(request.scope).toBe('read');
    expect(request.mode).toBe('development');
    expect(typeof request.secretHash).toBe('string');
    expect(request.secretHash.length).toBeGreaterThan(10);
    expect(request.pubJwk).toEqual(keypair.pubJwk);
  });
});


