import { describe, it, expect } from 'vitest';
import { generateKeypair, verifyPayload, importPublicKeyFromJwk, b64urlDecode, canonicalize } from '../../core/src/index.js';
import { BPCClient } from '../src/client.js';
import { prepareRegistration } from '../src/registration.js';
import type { BPCKeypair } from '../../core/src/index.js';

describe('BPCClient.signRequest', () => {
  let keypair: BPCKeypair;
  let client: BPCClient;

  it('should produce all three required BPC headers', async () => {
    keypair = await generateKeypair();
    client = new BPCClient({
      serverUrl: 'http://localhost:3000',
      pairId: 'pair_test123',
      keypair,
      secret: 'test-secret',
    });

    const headers = await client.signRequest('GET', '/api/status');

    expect(headers['X-BPC-Pair-ID']).toBe('pair_test123');
    expect(typeof headers['X-BPC-Signature']).toBe('string');
    expect(headers['X-BPC-Signature'].length).toBeGreaterThan(20);
    expect(typeof headers['X-BPC-Signed-Data']).toBe('string');
    expect(headers['X-BPC-Signed-Data'].length).toBeGreaterThan(20);
  });

  it('should produce a verifiable ECDSA signature', async () => {
    keypair = await generateKeypair();
    client = new BPCClient({
      serverUrl: 'http://localhost:3000',
      pairId: 'pair_verify_test',
      keypair,
      secret: 'verify-secret',
    });

    const headers = await client.signRequest('POST', '/api/data', { key: 'value' });

    // Decode the signed data to get the payload
    const signedDataJson = new TextDecoder().decode(b64urlDecode(headers['X-BPC-Signed-Data']));
    const payload = JSON.parse(signedDataJson);

    // Verify the signature using the public key
    const pubKey = await importPublicKeyFromJwk(keypair.pubJwk);
    const valid = await verifyPayload(pubKey, payload, headers['X-BPC-Signature']);
    expect(valid).toBe(true);
  });

  it('should produce a different nonce on each request', async () => {
    keypair = await generateKeypair();
    client = new BPCClient({
      serverUrl: 'http://localhost:3000',
      pairId: 'pair_nonce_test',
      keypair,
      secret: 'nonce-secret',
    });

    const h1 = await client.signRequest('GET', '/api/status');
    const h2 = await client.signRequest('GET', '/api/status');

    // Different signed data means different nonce/timestamp
    expect(h1['X-BPC-Signed-Data']).not.toBe(h2['X-BPC-Signed-Data']);

    // Decode and confirm nonces differ
    const p1 = JSON.parse(new TextDecoder().decode(b64urlDecode(h1['X-BPC-Signed-Data'])));
    const p2 = JSON.parse(new TextDecoder().decode(b64urlDecode(h2['X-BPC-Signed-Data'])));
    expect(p1.nonce).not.toBe(p2.nonce);
  });

  it('should include correct method and path in the payload', async () => {
    keypair = await generateKeypair();
    client = new BPCClient({
      serverUrl: 'http://localhost:3000',
      pairId: 'pair_mp_test',
      keypair,
      secret: 'mp-secret',
    });

    const headers = await client.signRequest('DELETE', '/api/resource/42');
    const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(headers['X-BPC-Signed-Data'])));

    expect(payload.method).toBe('DELETE');
    expect(payload.path).toBe('/api/resource/42');
    expect(payload.pair_id).toBe('pair_mp_test');
  });

  it('should produce canonical (sorted-key) JSON in signed data', async () => {
    keypair = await generateKeypair();
    client = new BPCClient({
      serverUrl: 'http://localhost:3000',
      pairId: 'pair_canonical_test',
      keypair,
      secret: 'canonical-secret',
    });

    const headers = await client.signRequest('GET', '/test');
    const signedJson = new TextDecoder().decode(b64urlDecode(headers['X-BPC-Signed-Data']));
    const keys = Object.keys(JSON.parse(signedJson));

    // Keys must be alphabetically sorted per BPC canonical form
    const sorted = [...keys].sort();
    expect(keys).toEqual(sorted);
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
