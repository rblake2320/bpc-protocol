import { describe, it, expect } from 'vitest';
import { BPCClient } from '../src/client.js';
import { BPC_PROTOCOL_VERSION, generateKeypair, b64urlDecode } from '../../core/src/index.js';
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
