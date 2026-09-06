import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  canonicalOpDigest,
  canonicalize,
  type OutboxRecord,
  type ReceiverDecision,
  type SanitizedMutation,
} from '../src/ha-outbox-contract.js';
import type { AckReceipt, AckReceiptVerifier } from '../src/ha-outbox-pg.js';
import {
  AckVerificationUnavailableError,
  HttpOutboxTransport,
  OutboxTransportError,
  createMemoryReplayNonceStoreForTests,
  createHttpOutboxReceiver,
  type HttpOutboxReceiverOptions,
} from '../src/http-outbox-transport.js';

interface PairMutation { pairId: string }
const STREAM = 'bpc:pair:http/v1';
function record(sequence = 1): OutboxRecord<PairMutation> {
  const mutation = { pairId: `pair-${sequence}` } as SanitizedMutation<PairMutation>;
  const opDigest = canonicalOpDigest({
    streamId: STREAM,
    sourceEpoch: 'e1',
    sequence,
    fenceToken: '0',
    mutation,
  });
  return {
    contractVersion: '1', streamId: STREAM, sourceEpoch: 'e1', sequence,
    fenceToken: '0', opDigest, mutation,
  };
}

const REQUEST_KEY_ID = 'request-1';
const RESPONSE_KEY_ID = 'response-1';
const requestSecret = Buffer.alloc(32, 11);
const responseSecret = Buffer.alloc(32, 17);
const receiptSecret = Buffer.alloc(32, 23);
function framed(...parts: string[]): Buffer {
  const chunks: Buffer[] = [];
  for (const value of parts) {
    const bytes = Buffer.from(value);
    const size = Buffer.alloc(4);
    size.writeUInt32BE(bytes.length);
    chunks.push(size, bytes);
  }
  return Buffer.concat(chunks);
}
function receiptBody(value: Omit<AckReceipt, 'signature'>): string {
  return [value.receiverId, value.keyId, value.streamId, value.sourceEpoch,
    value.sequence, value.opDigest, value.decision, value.issuedAt].join('|');
}
function signedReceipt(input: OutboxRecord<unknown>, decision: ReceiverDecision): AckReceipt {
  const value: Omit<AckReceipt, 'signature'> = {
    streamId: input.streamId, sourceEpoch: input.sourceEpoch,
    sequence: input.sequence, opDigest: input.opDigest, decision,
    receiverId: 'receiver-b', keyId: 'receipt-1', issuedAt: '1700000000000',
  };
  return {
    ...value,
    signature: createHmac('sha256', receiptSecret).update(receiptBody(value)).digest('base64url'),
  };
}
const receiptVerifier: AckReceiptVerifier = {
  async verify(value, delivered) {
    const expected = signedReceipt(delivered, value.decision);
    const actual = Buffer.from(value.signature, 'base64url');
    const signature = Buffer.from(expected.signature, 'base64url');
    if (value.receiverId !== expected.receiverId || value.keyId !== expected.keyId
      || actual.length !== signature.length || !timingSafeEqual(actual, signature)) {
      throw new Error('invalid receiver receipt');
    }
  },
};

let server: Server;
let url: string;
let handler: ReturnType<typeof createHttpOutboxReceiver>;
function install(overrides: Partial<HttpOutboxReceiverOptions> = {}): void {
  handler = createHttpOutboxReceiver({
    expectedPath: '/bpc/outbox',
    resolveRequestKey: (keyId) => keyId === REQUEST_KEY_ID ? requestSecret : null,
    responseKeyId: RESPONSE_KEY_ID,
    responseSecret,
    nonceStore: createMemoryReplayNonceStoreForTests(),
    receive: async (value) => signedReceipt(value, 'applied'),
    ...overrides,
  });
}
function client(overrides: Partial<ConstructorParameters<typeof HttpOutboxTransport>[0]> = {}): HttpOutboxTransport {
  return new HttpOutboxTransport({
    url,
    fetch: fetch as never,
    requestKeyId: REQUEST_KEY_ID,
    requestSecret,
    resolveResponseKey: (keyId) => keyId === RESPONSE_KEY_ID ? responseSecret : null,
    ackVerifier: receiptVerifier,
    ...overrides,
  });
}

beforeAll(async () => {
  install();
  server = createServer((req, res) => handler(req, res));
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  url = `http://127.0.0.1:${(server.address() as AddressInfo).port}/bpc/outbox`;
});
beforeEach(() => install());
afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

describe('authenticated BPC durable-outbox HTTP transport', () => {
  it('delivers a canonical record and returns a decision-bound signed receipt', async () => {
    await expect(client().deliverAndAwaitAck(record())).resolves.toMatchObject({
      decision: 'applied', sequence: 1,
    });
  });

  it('rejects bad request authentication as terminal', async () => {
    const error = await client({ requestSecret: Buffer.alloc(32, 99) })
      .deliverAndAwaitAck(record()).catch((value) => value);
    expect(error).toBeInstanceOf(OutboxTransportError);
    expect(error.retriable).toBe(false);
  });

  it('burns each nonce exactly once before semantic processing', async () => {
    const sameNonce = client({ nonce: () => 'fixed-nonce-abcdefghijklmnop' });
    await sameNonce.deliverAndAwaitAck(record());
    await expect(sameNonce.deliverAndAwaitAck(record())).rejects.toBeInstanceOf(OutboxTransportError);
  });

  it('rejects stale timestamps and wrong paths', async () => {
    await expect(client({ now: () => 1 }).deliverAndAwaitAck(record()))
      .rejects.toBeInstanceOf(OutboxTransportError);
    await expect(client({ url: url.replace('/bpc/outbox', '/wrong') }).deliverAndAwaitAck(record()))
      .rejects.toBeInstanceOf(OutboxTransportError);
  });

  it.each([Number.NaN, Number.POSITIVE_INFINITY, Number.MAX_SAFE_INTEGER + 1])(
    'fails closed when the receiver clock is invalid (%s)',
    async (badNow) => {
      install({ now: () => badNow });
      const error = await client().deliverAndAwaitAck(record()).catch((value) => value);
      expect(error).toBeInstanceOf(OutboxTransportError);
      expect(error.retriable).toBe(false);
    },
  );

  it.each(['+1000', '1e3', ' 1000', '01000'])(
    'rejects a noncanonical authenticated timestamp (%s)',
    async (timestamp) => {
      install({ now: () => 1_000 });
      const body = canonicalize(record());
      const digest = createHash('sha256').update(body).digest('hex');
      const signature = createHmac('sha256', requestSecret)
        .update(framed('BPCv1-req', REQUEST_KEY_ID, 'POST', '/bpc/outbox', timestamp,
          'manual-nonce-abcdefghijklmnop', digest))
        .digest('base64url');
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'content-type': 'application/json', 'x-bpc-key-id': REQUEST_KEY_ID,
          'x-bpc-timestamp': timestamp, 'x-bpc-nonce': 'manual-nonce-abcdefghijklmnop',
          'x-bpc-signature': signature,
        },
        body,
      });
      expect(response.status).toBe(401);
    },
  );

  it('rejects a receipt that is not bound to the delivered record', async () => {
    install({ receive: async () => signedReceipt(record(2), 'applied') });
    await expect(client().deliverAndAwaitAck(record(1))).rejects.toThrow(/bind/);
  });

  it('rejects a forged decision receipt', async () => {
    install({ receive: async (value) => ({ ...signedReceipt(value, 'applied'), signature: 'AAAA' }) });
    await expect(client().deliverAndAwaitAck(record())).rejects.toBeInstanceOf(OutboxTransportError);
  });

  it('treats only a typed acknowledgement-verifier outage as retriable', async () => {
    const unavailable: AckReceiptVerifier = {
      async verify() { throw new AckVerificationUnavailableError(); },
    };
    const error = await client({ ackVerifier: unavailable })
      .deliverAndAwaitAck(record()).catch((value) => value);
    expect(error).toBeInstanceOf(OutboxTransportError);
    expect(error.retriable).toBe(true);
  });

  it('snapshots the delivered record synchronously before any network await', async () => {
    const mutable = record() as OutboxRecord<PairMutation>;
    let observedPair = '';
    install({ receive: async (value) => {
      observedPair = (value.mutation as PairMutation).pairId;
      return signedReceipt(value, 'applied');
    } });
    const mutatingFetch = async (...args: Parameters<typeof fetch>) => {
      (mutable.mutation as PairMutation).pairId = 'mutated-after-dispatch';
      return fetch(...args);
    };
    await client({ fetch: mutatingFetch as never }).deliverAndAwaitAck(mutable);
    expect(observedPair).toBe('pair-1');
  });

  it('rejects an accessor-backed receiver receipt before response signing', async () => {
    install({ receive: async (value) => {
      const valid = signedReceipt(value, 'applied');
      const hostile = { ...valid } as Record<string, unknown>;
      Object.defineProperty(hostile, 'decision', { enumerable: true, get: () => 'applied' });
      return hostile as unknown as AckReceipt;
    } });
    const error = await client().deliverAndAwaitAck(record()).catch((value) => value);
    expect(error).toBeInstanceOf(OutboxTransportError);
    expect(error.retriable).toBe(true);
  });

  it('classifies network and server failure as retriable', async () => {
    install({ receive: async () => { throw new Error('receiver unavailable'); } });
    const serverError = await client().deliverAndAwaitAck(record()).catch((value) => value);
    expect(serverError.retriable).toBe(true);
    const networkError = await client({ url: 'http://127.0.0.1:9/bpc/outbox', timeoutMs: 200 })
      .deliverAndAwaitAck(record()).catch((value) => value);
    expect(networkError.retriable).toBe(true);
  });

  it('bounds the full exchange and cancels a non-terminating response stream', async () => {
    const hangingFetch = async () => ({
      status: 200,
      headers: { get: () => 'application/json' },
      body: new ReadableStream<Uint8Array>({ pull: () => new Promise<void>(() => {}) }),
    });
    const error = await client({ fetch: hangingFetch, timeoutMs: 50 })
      .deliverAndAwaitAck(record()).catch((value) => value);
    expect(error).toBeInstanceOf(OutboxTransportError);
    expect(error.retriable).toBe(true);
  });

  it('supports overlapping request and response keys during rotation', async () => {
    const nextRequestSecret = Buffer.alloc(32, 31);
    install({ resolveRequestKey: (keyId) =>
      keyId === REQUEST_KEY_ID ? requestSecret : keyId === 'request-2' ? nextRequestSecret : null });
    await expect(client({ requestKeyId: 'request-2', requestSecret: nextRequestSecret })
      .deliverAndAwaitAck(record())).resolves.toMatchObject({ decision: 'applied' });
  });

  it('fails composition when replay retention cannot cover freshness and skew', () => {
    expect(() => createHttpOutboxReceiver({
      expectedPath: '/bpc/outbox', resolveRequestKey: () => requestSecret,
      responseKeyId: RESPONSE_KEY_ID, responseSecret,
      nonceStore: createMemoryReplayNonceStoreForTests(1_000), freshnessMs: 30_000,
      receive: async (value) => signedReceipt(value, 'applied'),
    })).toThrow(/retention/);
  });
});
