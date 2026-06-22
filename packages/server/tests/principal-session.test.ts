import { describe, expect, it } from 'vitest';
import { computeFingerprint, generateKeypair, signPayload } from '../../core/src/index.js';
import {
  buildPrincipalSessionProofPayload,
  createBPCServer,
  MemoryPrincipalSessionLedger,
  sealPrincipalCache,
  verifyFallbackAuthorization,
  type BindSessionInput,
} from '../src/index.js';

async function bindingInput(
  overrides: Partial<BindSessionInput> = {},
  keypair: Awaited<ReturnType<typeof generateKeypair>> | undefined = undefined,
): Promise<BindSessionInput> {
  keypair ??= await generateKeypair();
  const keyFingerprint = await computeFingerprint(keypair.pubJwk);
  const signedAt = Date.now();
  const provider = overrides.provider ?? 'codex';
  const providerSessionId = overrides.providerSessionId ?? 'abc-123';
  const agentInstanceId = overrides.agentInstanceId ?? `${provider}:${providerSessionId}`;
  const policyDigest = overrides.policyDigest ?? 'policy:v1:test';
  const challengeNonce = overrides.proof?.challengeNonce ?? 'nonce-1234567890abcdef';
  const payload = buildPrincipalSessionProofPayload({
    keyFingerprint,
    provider,
    providerSessionId,
    agentInstanceId,
    policyDigest,
    challengeNonce,
    signedAt,
  });

  return {
    publicKeyJwk: keypair.pubJwk,
    provider,
    providerSessionId,
    agentInstanceId,
    policyDigest,
    proof: {
      challengeNonce,
      signedAt,
      signature: await signPayload(keypair.privateKey, payload),
    },
    ...overrides,
  };
}

describe('principal session ledger', () => {
  it('requires a fresh signed proof before binding a provider session', async () => {
    const ledger = new MemoryPrincipalSessionLedger();
    const input = await bindingInput({
      authorizationContext: { role: 'mesh-agent', scope: 'admin' },
      runtimeMetadata: { tool: 'codex', model: 'gpt-5.5' },
    });

    const binding = await ledger.bindSession(input);

    expect(binding.provider).toBe('codex');
    expect(binding.providerSessionId).toBe('abc-123');
    expect(binding.authorizationContext.role).toBe('mesh-agent');
    expect(binding.bindingHash).toMatch(/^[0-9a-f]{64}$/);
    expect(await ledger.verifyPrincipalContinuity(binding.principalId)).toEqual({
      valid: true,
      principalId: binding.principalId,
    });
  });

  it('fails closed on a stale or invalid session proof', async () => {
    const ledger = new MemoryPrincipalSessionLedger();
    const input = await bindingInput();

    await expect(
      ledger.bindSession({
        ...input,
        proof: { ...input.proof, signedAt: Date.now() - 10 * 60_000 },
      }),
    ).rejects.toThrow('expired');

    await expect(
      ledger.bindSession({
        ...input,
        proof: { ...input.proof, signature: 'not-a-real-signature' },
      }),
    ).rejects.toThrow('invalid');
  });

  it('partitions concurrent sessions into distinct streams under one principal', async () => {
    const ledger = new MemoryPrincipalSessionLedger();
    const keypair = await generateKeypair();
    const first = await bindingInput({
      provider: 'codex',
      providerSessionId: 'abc-123',
      agentInstanceId: 'forge-worker-a',
    }, keypair);
    const second = await bindingInput({
      provider: 'claude',
      providerSessionId: 'def-456',
      agentInstanceId: 'forge-worker-b',
    }, keypair);

    const firstBinding = await ledger.bindSession(first);
    const secondBinding = await ledger.bindSession(second);

    expect(secondBinding.principalId).toBe(firstBinding.principalId);
    expect(secondBinding.streamId).not.toBe(firstBinding.streamId);

    const principal = await ledger.getPrincipal(firstBinding.principalId);
    expect(principal?.sessionIds).toEqual(['abc-123', 'def-456']);
    expect(principal?.streamIds).toHaveLength(2);
    expect(await ledger.verifyPrincipalContinuity(firstBinding.principalId)).toEqual({
      valid: true,
      principalId: firstBinding.principalId,
    });
  });

  it('detects tampering in any concurrent stream or checkpoint', async () => {
    const ledger = new MemoryPrincipalSessionLedger();
    const binding = await ledger.bindSession(await bindingInput());
    await ledger.appendStreamEvent(binding.principalId, binding.streamId, 'session_event', { action: 'did-work' });

    const snapshot = ledger.snapshotStream(binding.streamId);
    snapshot[1].payload = { action: 'tampered' };
    (ledger as unknown as { events: Map<string, typeof snapshot> }).events.set(binding.streamId, snapshot);

    const result = await ledger.verifyPrincipalContinuity(binding.principalId);
    expect(result.valid).toBe(false);
    expect(result.reason).toBe('stream_entry_hash_mismatch');
  });

  it('factory exposes the principal ledger without changing existing server parts', () => {
    const server = createBPCServer();
    expect(server.registry).toBeDefined();
    expect(server.auditLog).toBeDefined();
    expect(server.principalLedger).toBeInstanceOf(MemoryPrincipalSessionLedger);
  });

  it('sealed fallback cache enforces same-policy checks and fails closed', async () => {
    const ledger = new MemoryPrincipalSessionLedger();
    const binding = await ledger.bindSession(await bindingInput());
    const now = Date.now();
    const sealKey = 'local-seal-key';
    const cache = sealPrincipalCache({
      source: 'sealed_cache',
      principalId: binding.principalId,
      policyDigest: binding.policyDigest,
      checkpointHash: binding.checkpointHash,
      issuedAt: now - 1000,
      expiresAt: now + 60_000,
      sealKey,
    });

    expect(verifyFallbackAuthorization({
      cache,
      sealKey,
      requestedPolicyDigest: binding.policyDigest,
      expectedCheckpointHash: binding.checkpointHash,
      challengeNonce: 'nonce-1234567890abcdef',
      proofVerified: true,
      nowMs: now,
    }).ok).toBe(true);

    expect(verifyFallbackAuthorization({
      cache: { ...cache, policyDigest: 'tampered' },
      sealKey,
      requestedPolicyDigest: binding.policyDigest,
      expectedCheckpointHash: binding.checkpointHash,
      challengeNonce: 'nonce-1234567890abcdef',
      proofVerified: true,
      nowMs: now,
    }).error).toBe('cache_seal_invalid');

    expect(verifyFallbackAuthorization({
      cache,
      sealKey,
      requestedPolicyDigest: 'policy:other',
      expectedCheckpointHash: binding.checkpointHash,
      challengeNonce: 'nonce-1234567890abcdef',
      proofVerified: true,
      nowMs: now,
    }).error).toBe('policy_mismatch');

    expect(verifyFallbackAuthorization({
      cache,
      sealKey,
      requestedPolicyDigest: binding.policyDigest,
      expectedCheckpointHash: binding.checkpointHash,
      challengeNonce: 'nonce-1234567890abcdef',
      proofVerified: false,
      nowMs: now,
    }).error).toBe('fresh_proof_required');
  });
});
