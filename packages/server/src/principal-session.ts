import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import {
  collectRuntimeMetadata,
  computeFingerprint,
  importPublicKeyFromJwk,
  sanitizeCaptureValue,
  verifyPayload,
} from '@bpc/core';
import type { AIRuntimeMetadata } from '@bpc/core';

export const PRINCIPAL_GENESIS_HASH = '0'.repeat(64);
export const PRINCIPAL_BINDING_PURPOSE = 'bpc.principal.session.bind.v1';

export interface AuthorizationContext {
  role?: string;
  scope?: string;
  permissions?: string[];
  policy?: Record<string, unknown>;
}

export interface PrincipalRecord {
  principalId: string;
  keyFingerprint: string;
  publicKeyJwk: JsonWebKey;
  createdAt: number;
  updatedAt: number;
  authorizationContext: AuthorizationContext;
  keyVersion: number;
  sessionIds: string[];
  activeSessionIds: string[];
  streamIds: string[];
  checkpointHead: string;
  checkpointSeq: number;
}

export interface PrincipalStreamRecord {
  principalId: string;
  streamId: string;
  provider: string;
  agentInstanceId: string;
  providerSessionIds: string[];
  seq: number;
  headHash: string;
}

export interface PrincipalSessionProof {
  challengeNonce: string;
  signedAt: number;
  signature: string;
}

export interface PrincipalSessionProofPayload extends Record<string, unknown> {
  purpose: typeof PRINCIPAL_BINDING_PURPOSE;
  key_fingerprint: string;
  provider: string;
  provider_session_id: string;
  agent_instance_id: string;
  policy_digest: string;
  challenge_nonce: string;
  signed_at: number;
}

export interface BindSessionInput {
  publicKeyJwk: JsonWebKey;
  proof: PrincipalSessionProof;
  provider: string;
  providerSessionId: string;
  agentInstanceId?: string;
  policyDigest: string;
  runtimeMetadata?: Partial<AIRuntimeMetadata>;
  authorizationContext?: AuthorizationContext;
  maxProofAgeMs?: number;
}

export type PrincipalEventType =
  | 'session_bound'
  | 'session_event'
  | 'session_closed'
  | 'key_rotated'
  | 'authorization_updated';

export interface PrincipalStreamEvent {
  principalId: string;
  streamId: string;
  provider: string;
  providerSessionId?: string;
  agentInstanceId: string;
  seq: number;
  timestamp: number;
  eventType: PrincipalEventType;
  policyDigest?: string;
  proofDigest?: string;
  payloadHash: string;
  payload?: Record<string, unknown>;
  prevHash: string;
  chainHash: string;
  /** Alias used by session binding callers. Equal to chainHash on SESSION_BOUND. */
  bindingHash?: string;
}

export interface PrincipalCheckpoint {
  principalId: string;
  seq: number;
  timestamp: number;
  streamHeads: Record<string, { seq: number; chainHash: string }>;
  prevHash: string;
  checkpointHash: string;
}

export interface SessionBinding {
  principalId: string;
  streamId: string;
  provider: string;
  providerSessionId: string;
  agentInstanceId: string;
  boundAt: number;
  policyDigest: string;
  authorizationContext: AuthorizationContext;
  runtime: AIRuntimeMetadata;
  prevHash: string;
  bindingHash: string;
  checkpointHash: string;
}

export interface PrincipalChainVerifyResult {
  valid: boolean;
  principalId?: string;
  brokenAt?: string;
  reason?: string;
}

export interface SealedPrincipalCache {
  version: '1';
  source: 'replica' | 'sealed_cache';
  principalId: string;
  policyDigest: string;
  checkpointHash: string;
  issuedAt: number;
  expiresAt: number;
  consumedNonceDigests: string[];
  authorizationContext: AuthorizationContext;
  seal: string;
}

export interface SealPrincipalCacheInput {
  source: 'replica' | 'sealed_cache';
  principalId: string;
  policyDigest: string;
  checkpointHash: string;
  issuedAt: number;
  expiresAt: number;
  consumedNonceDigests?: string[];
  authorizationContext?: AuthorizationContext;
  sealKey: string;
}

export interface FallbackAuthorizationInput {
  cache: SealedPrincipalCache;
  sealKey: string;
  requestedPolicyDigest: string;
  expectedCheckpointHash: string;
  challengeNonce: string;
  proofVerified: boolean;
  nowMs?: number;
}

export interface FallbackAuthorizationResult {
  ok: boolean;
  source?: SealedPrincipalCache['source'];
  authorizationContext?: AuthorizationContext;
  error?: string;
}

export interface PrincipalSessionLedger {
  bindSession(input: BindSessionInput): Promise<SessionBinding>;
  appendStreamEvent(
    principalId: string,
    streamId: string,
    eventType: PrincipalEventType,
    payload?: Record<string, unknown>,
  ): Promise<PrincipalStreamEvent>;
  closeSession(principalId: string, streamId: string, providerSessionId: string): Promise<void>;
  rotatePrincipalKey(principalId: string, publicKeyJwk: JsonWebKey, keyVersion?: number): Promise<PrincipalRecord>;
  getPrincipal(principalId: string): Promise<PrincipalRecord | undefined>;
  queryPrincipalEvents(principalId: string, limit?: number): Promise<PrincipalStreamEvent[]>;
  verifyPrincipalContinuity(principalId: string): Promise<PrincipalChainVerifyResult>;
}

export class MemoryPrincipalSessionLedger implements PrincipalSessionLedger {
  private principals = new Map<string, PrincipalRecord>();
  private streams = new Map<string, PrincipalStreamRecord>();
  private events = new Map<string, PrincipalStreamEvent[]>();
  private checkpoints = new Map<string, PrincipalCheckpoint[]>();

  async bindSession(input: BindSessionInput): Promise<SessionBinding> {
    assertBindingInput(input);

    const keyFingerprint = await computeFingerprint(input.publicKeyJwk);
    await verifyPrincipalSessionProof(input, keyFingerprint);

    const principal = await this.upsertPrincipal(input.publicKeyJwk, keyFingerprint, input.authorizationContext);
    const agentInstanceId = input.agentInstanceId ?? `${input.provider}:${input.providerSessionId}`;
    const streamId = makeStreamId(principal.principalId, input.provider, agentInstanceId);
    const stream = this.upsertStream(principal, streamId, input.provider, agentInstanceId, input.providerSessionId);

    if (!principal.sessionIds.includes(input.providerSessionId)) {
      principal.sessionIds.push(input.providerSessionId);
    }
    if (!principal.activeSessionIds.includes(input.providerSessionId)) {
      principal.activeSessionIds.push(input.providerSessionId);
    }
    if (input.authorizationContext) {
      principal.authorizationContext = { ...principal.authorizationContext, ...input.authorizationContext };
    }

    const runtime = collectRuntimeMetadata(input.runtimeMetadata ?? {});
    const proofDigest = sha256hex(canonicalJson(input.proof));
    const payload = {
      provider: input.provider,
      providerSessionId: input.providerSessionId,
      agentInstanceId,
      policyDigest: input.policyDigest,
      runtime,
      authorizationContext: principal.authorizationContext,
    };
    const event = this.appendEventToStream(stream, 'session_bound', payload, {
      providerSessionId: input.providerSessionId,
      policyDigest: input.policyDigest,
      proofDigest,
      binding: true,
    });
    const checkpoint = this.appendCheckpoint(principal);

    return {
      principalId: principal.principalId,
      streamId,
      provider: input.provider,
      providerSessionId: input.providerSessionId,
      agentInstanceId,
      boundAt: event.timestamp,
      policyDigest: input.policyDigest,
      authorizationContext: principal.authorizationContext,
      runtime,
      prevHash: event.prevHash,
      bindingHash: event.chainHash,
      checkpointHash: checkpoint.checkpointHash,
    };
  }

  async appendStreamEvent(
    principalId: string,
    streamId: string,
    eventType: PrincipalEventType,
    payload: Record<string, unknown> = {},
  ): Promise<PrincipalStreamEvent> {
    const principal = this.mustPrincipal(principalId);
    const stream = this.streams.get(streamId);
    if (!stream || stream.principalId !== principalId) {
      throw new Error(`Unknown stream for principal: ${streamId}`);
    }
    const event = this.appendEventToStream(stream, eventType, payload);
    this.appendCheckpoint(principal);
    return event;
  }

  async closeSession(principalId: string, streamId: string, providerSessionId: string): Promise<void> {
    const principal = this.mustPrincipal(principalId);
    principal.activeSessionIds = principal.activeSessionIds.filter(id => id !== providerSessionId);
    await this.appendStreamEvent(principalId, streamId, 'session_closed', { providerSessionId });
  }

  async rotatePrincipalKey(principalId: string, publicKeyJwk: JsonWebKey, keyVersion?: number): Promise<PrincipalRecord> {
    const principal = this.mustPrincipal(principalId);
    principal.publicKeyJwk = publicKeyJwk;
    principal.keyFingerprint = await computeFingerprint(publicKeyJwk);
    principal.keyVersion = keyVersion ?? principal.keyVersion + 1;
    principal.updatedAt = Date.now();
    this.appendCheckpoint(principal);
    return principal;
  }

  async getPrincipal(principalId: string): Promise<PrincipalRecord | undefined> {
    return this.principals.get(principalId);
  }

  async queryPrincipalEvents(principalId: string, limit = 1000): Promise<PrincipalStreamEvent[]> {
    const principal = this.mustPrincipal(principalId);
    return principal.streamIds
      .flatMap(streamId => this.events.get(streamId) ?? [])
      .sort((a, b) => a.timestamp - b.timestamp || a.streamId.localeCompare(b.streamId) || a.seq - b.seq)
      .slice(-limit);
  }

  async verifyPrincipalContinuity(principalId: string): Promise<PrincipalChainVerifyResult> {
    const principal = this.principals.get(principalId);
    if (!principal) return { valid: false, principalId, reason: 'principal_not_found' };

    const currentHeads: Record<string, { seq: number; chainHash: string }> = {};
    for (const streamId of principal.streamIds) {
      const stream = this.streams.get(streamId);
      const entries = this.events.get(streamId) ?? [];
      if (!stream) return { valid: false, principalId, brokenAt: streamId, reason: 'stream_missing' };

      let prevHash = PRINCIPAL_GENESIS_HASH;
      for (let i = 0; i < entries.length; i++) {
        const event = entries[i];
        if (event.seq !== i + 1) {
          return { valid: false, principalId, brokenAt: `${streamId}:${event.seq}`, reason: 'non_contiguous_stream_seq' };
        }
        if (event.prevHash !== prevHash) {
          return { valid: false, principalId, brokenAt: `${streamId}:${event.seq}`, reason: 'broken_stream_link' };
        }
        if (computeStreamEventHash(event) !== event.chainHash) {
          return { valid: false, principalId, brokenAt: `${streamId}:${event.seq}`, reason: 'stream_entry_hash_mismatch' };
        }
        prevHash = event.chainHash;
      }
      if (stream.seq !== entries.length || stream.headHash !== prevHash) {
        return { valid: false, principalId, brokenAt: streamId, reason: 'stream_head_mismatch' };
      }
      currentHeads[streamId] = { seq: stream.seq, chainHash: stream.headHash };
    }

    let checkpointPrev = PRINCIPAL_GENESIS_HASH;
    const checkpoints = this.checkpoints.get(principalId) ?? [];
    for (let i = 0; i < checkpoints.length; i++) {
      const checkpoint = checkpoints[i];
      if (checkpoint.seq !== i + 1) {
        return { valid: false, principalId, brokenAt: `checkpoint:${checkpoint.seq}`, reason: 'non_contiguous_checkpoint_seq' };
      }
      if (checkpoint.prevHash !== checkpointPrev) {
        return { valid: false, principalId, brokenAt: `checkpoint:${checkpoint.seq}`, reason: 'broken_checkpoint_link' };
      }
      if (computeCheckpointHash(checkpoint) !== checkpoint.checkpointHash) {
        return { valid: false, principalId, brokenAt: `checkpoint:${checkpoint.seq}`, reason: 'checkpoint_hash_mismatch' };
      }
      checkpointPrev = checkpoint.checkpointHash;
    }

    const latest = checkpoints.at(-1);
    if (!latest || latest.checkpointHash !== principal.checkpointHead || latest.seq !== principal.checkpointSeq) {
      return { valid: false, principalId, brokenAt: 'checkpoint:head', reason: 'principal_checkpoint_head_mismatch' };
    }
    if (canonicalJson(latest.streamHeads) !== canonicalJson(currentHeads)) {
      return { valid: false, principalId, brokenAt: 'checkpoint:latest', reason: 'checkpoint_stream_heads_mismatch' };
    }

    return { valid: true, principalId };
  }

  /** Test/inspection helper. Do not mutate returned objects in production. */
  snapshotStream(streamId: string): PrincipalStreamEvent[] {
    return [...(this.events.get(streamId) ?? [])].map(event => ({ ...event }));
  }

  /** Test/inspection helper. Do not mutate returned objects in production. */
  snapshotCheckpoints(principalId: string): PrincipalCheckpoint[] {
    return [...(this.checkpoints.get(principalId) ?? [])].map(checkpoint => ({ ...checkpoint }));
  }

  private async upsertPrincipal(
    publicKeyJwk: JsonWebKey,
    keyFingerprint: string,
    authorizationContext: AuthorizationContext = {},
  ): Promise<PrincipalRecord> {
    const principalId = principalIdFromFingerprint(keyFingerprint);
    const existing = this.principals.get(principalId);
    if (existing) return existing;

    const now = Date.now();
    const principal: PrincipalRecord = {
      principalId,
      keyFingerprint,
      publicKeyJwk,
      createdAt: now,
      updatedAt: now,
      authorizationContext,
      keyVersion: 1,
      sessionIds: [],
      activeSessionIds: [],
      streamIds: [],
      checkpointHead: PRINCIPAL_GENESIS_HASH,
      checkpointSeq: 0,
    };
    this.principals.set(principalId, principal);
    this.checkpoints.set(principalId, []);
    return principal;
  }

  private upsertStream(
    principal: PrincipalRecord,
    streamId: string,
    provider: string,
    agentInstanceId: string,
    providerSessionId: string,
  ): PrincipalStreamRecord {
    const existing = this.streams.get(streamId);
    if (existing) {
      if (!existing.providerSessionIds.includes(providerSessionId)) {
        existing.providerSessionIds.push(providerSessionId);
      }
      return existing;
    }

    const stream: PrincipalStreamRecord = {
      principalId: principal.principalId,
      streamId,
      provider,
      agentInstanceId,
      providerSessionIds: [providerSessionId],
      seq: 0,
      headHash: PRINCIPAL_GENESIS_HASH,
    };
    this.streams.set(streamId, stream);
    this.events.set(streamId, []);
    principal.streamIds.push(streamId);
    return stream;
  }

  private appendEventToStream(
    stream: PrincipalStreamRecord,
    eventType: PrincipalEventType,
    payload: Record<string, unknown>,
    options: {
      providerSessionId?: string;
      policyDigest?: string;
      proofDigest?: string;
      binding?: boolean;
    } = {},
  ): PrincipalStreamEvent {
    const sanitizedPayload = sanitizeCaptureValue(payload) as Record<string, unknown>;
    const seq = stream.seq + 1;
    const timestamp = Date.now();
    const base: Omit<PrincipalStreamEvent, 'chainHash' | 'bindingHash'> = {
      principalId: stream.principalId,
      streamId: stream.streamId,
      provider: stream.provider,
      providerSessionId: options.providerSessionId,
      agentInstanceId: stream.agentInstanceId,
      seq,
      timestamp,
      eventType,
      policyDigest: options.policyDigest,
      proofDigest: options.proofDigest,
      payloadHash: sha256hex(canonicalJson(sanitizedPayload)),
      payload: sanitizedPayload,
      prevHash: stream.headHash,
    };
    const chainHash = computeStreamEventHash(base);
    const event: PrincipalStreamEvent = {
      ...base,
      chainHash,
      bindingHash: options.binding ? chainHash : undefined,
    };
    const entries = this.events.get(stream.streamId) ?? [];
    entries.push(event);
    this.events.set(stream.streamId, entries);
    stream.seq = seq;
    stream.headHash = chainHash;
    return event;
  }

  private appendCheckpoint(principal: PrincipalRecord): PrincipalCheckpoint {
    const existing = this.checkpoints.get(principal.principalId) ?? [];
    const streamHeads: Record<string, { seq: number; chainHash: string }> = {};
    for (const streamId of principal.streamIds) {
      const stream = this.streams.get(streamId);
      if (stream) streamHeads[streamId] = { seq: stream.seq, chainHash: stream.headHash };
    }
    const checkpoint: Omit<PrincipalCheckpoint, 'checkpointHash'> = {
      principalId: principal.principalId,
      seq: principal.checkpointSeq + 1,
      timestamp: Date.now(),
      streamHeads,
      prevHash: principal.checkpointHead,
    };
    const full: PrincipalCheckpoint = {
      ...checkpoint,
      checkpointHash: computeCheckpointHash(checkpoint),
    };
    existing.push(full);
    this.checkpoints.set(principal.principalId, existing);
    principal.checkpointSeq = full.seq;
    principal.checkpointHead = full.checkpointHash;
    principal.updatedAt = full.timestamp;
    return full;
  }

  private mustPrincipal(principalId: string): PrincipalRecord {
    const principal = this.principals.get(principalId);
    if (!principal) throw new Error(`Unknown principal: ${principalId}`);
    return principal;
  }
}

export function sealPrincipalCache(input: SealPrincipalCacheInput): SealedPrincipalCache {
  const cache: Omit<SealedPrincipalCache, 'seal'> = {
    version: '1',
    source: input.source,
    principalId: input.principalId,
    policyDigest: input.policyDigest,
    checkpointHash: input.checkpointHash,
    issuedAt: input.issuedAt,
    expiresAt: input.expiresAt,
    consumedNonceDigests: input.consumedNonceDigests ?? [],
    authorizationContext: input.authorizationContext ?? {},
  };
  return { ...cache, seal: computeCacheSeal(cache, input.sealKey) };
}

export function verifyFallbackAuthorization(input: FallbackAuthorizationInput): FallbackAuthorizationResult {
  const now = input.nowMs ?? Date.now();
  const { seal: _seal, ...cacheBody } = input.cache;
  const expectedSeal = computeCacheSeal(cacheBody, input.sealKey);

  if (!constantTimeHexEqual(input.cache.seal, expectedSeal)) return { ok: false, error: 'cache_seal_invalid' };
  if (input.cache.issuedAt > now) return { ok: false, error: 'cache_not_yet_valid' };
  if (input.cache.expiresAt <= now) return { ok: false, error: 'cache_expired' };
  if (input.cache.policyDigest !== input.requestedPolicyDigest) return { ok: false, error: 'policy_mismatch' };
  if (input.cache.checkpointHash !== input.expectedCheckpointHash) return { ok: false, error: 'checkpoint_mismatch' };
  if (!input.proofVerified) return { ok: false, error: 'fresh_proof_required' };
  if (!input.challengeNonce || input.challengeNonce.length < 16) return { ok: false, error: 'nonce_too_short' };
  if (input.cache.consumedNonceDigests.includes(sha256hex(input.challengeNonce))) {
    return { ok: false, error: 'nonce_replay' };
  }

  return {
    ok: true,
    source: input.cache.source,
    authorizationContext: input.cache.authorizationContext,
  };
}

export async function verifyPrincipalSessionProof(input: BindSessionInput, keyFingerprint?: string): Promise<void> {
  const fingerprint = keyFingerprint ?? await computeFingerprint(input.publicKeyJwk);
  const maxProofAgeMs = input.maxProofAgeMs ?? 5 * 60_000;
  const age = Math.abs(Date.now() - input.proof.signedAt);
  if (age > maxProofAgeMs) {
    throw new Error('principal session proof expired');
  }
  if (!input.proof.challengeNonce || input.proof.challengeNonce.length < 16) {
    throw new Error('principal session proof nonce too short');
  }

  const payload = buildPrincipalSessionProofPayload({
    keyFingerprint: fingerprint,
    provider: input.provider,
    providerSessionId: input.providerSessionId,
    agentInstanceId: input.agentInstanceId ?? `${input.provider}:${input.providerSessionId}`,
    policyDigest: input.policyDigest,
    challengeNonce: input.proof.challengeNonce,
    signedAt: input.proof.signedAt,
  });
  const publicKey = await importPublicKeyFromJwk(input.publicKeyJwk);
  const ok = await verifyPayload(publicKey, payload, input.proof.signature);
  if (!ok) throw new Error('principal session proof invalid');
}

export function buildPrincipalSessionProofPayload(input: {
  keyFingerprint: string;
  provider: string;
  providerSessionId: string;
  agentInstanceId: string;
  policyDigest: string;
  challengeNonce: string;
  signedAt: number;
}): PrincipalSessionProofPayload {
  return {
    purpose: PRINCIPAL_BINDING_PURPOSE,
    key_fingerprint: input.keyFingerprint,
    provider: input.provider,
    provider_session_id: input.providerSessionId,
    agent_instance_id: input.agentInstanceId,
    policy_digest: input.policyDigest,
    challenge_nonce: input.challengeNonce,
    signed_at: input.signedAt,
  };
}

export function principalIdFromFingerprint(keyFingerprint: string): string {
  return `principal_${sha256hex(`bpc-principal-v1:${keyFingerprint}`).slice(0, 24)}`;
}

export function makeStreamId(principalId: string, provider: string, agentInstanceId: string): string {
  return `stream_${sha256hex(`${principalId}:${provider}:${agentInstanceId}`).slice(0, 24)}`;
}

function assertBindingInput(input: BindSessionInput): void {
  if (!input.provider || input.provider.trim() === '') throw new Error('provider is required');
  if (!input.providerSessionId || input.providerSessionId.trim() === '') throw new Error('providerSessionId is required');
  if (!input.policyDigest || input.policyDigest.trim() === '') throw new Error('policyDigest is required');
}

function computeStreamEventHash(event: Omit<PrincipalStreamEvent, 'chainHash' | 'bindingHash'>): string {
  return sha256hex(canonicalJson([
    event.seq,
    event.prevHash,
    event.principalId,
    event.streamId,
    event.provider,
    event.providerSessionId ?? null,
    event.agentInstanceId,
    event.timestamp,
    event.eventType,
    event.policyDigest ?? null,
    event.proofDigest ?? null,
    event.payloadHash,
    event.payload ?? {},
  ]));
}

function computeCheckpointHash(checkpoint: Omit<PrincipalCheckpoint, 'checkpointHash'>): string {
  return sha256hex(canonicalJson([
    checkpoint.seq,
    checkpoint.prevHash,
    checkpoint.principalId,
    checkpoint.timestamp,
    checkpoint.streamHeads,
  ]));
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = sortValue((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return value;
}

function sha256hex(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex');
}

function computeCacheSeal(cache: Omit<SealedPrincipalCache, 'seal'>, sealKey: string): string {
  return createHmac('sha256', sealKey).update(canonicalJson(cache), 'utf8').digest('hex');
}

function constantTimeHexEqual(a: string, b: string): boolean {
  const aBuf = Buffer.from(a, 'hex');
  const bBuf = Buffer.from(b, 'hex');
  if (aBuf.length !== bBuf.length) return false;
  return timingSafeEqual(aBuf, bBuf);
}
