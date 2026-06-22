import { describe, expect, it } from 'vitest';
import {
  CacheExpiredError,
  CacheTamperedError,
  CacheUnavailableError,
  DpapiFailClosedAgentCache,
  MemoryAgentCredentialCacheStore,
  computePermissionsHash,
  sealAgentCredentialCacheEntry,
  type DpapiProtector,
  type SealedAgentCredentialCache,
} from '../src/index.js';

class PlaintextCurrentUserProtector implements DpapiProtector {
  readonly scope = 'CurrentUser' as const;

  async protect(plaintext: Uint8Array): Promise<Uint8Array> {
    return Buffer.from(plaintext);
  }

  async unprotect(ciphertext: Uint8Array): Promise<Uint8Array> {
    return Buffer.from(ciphertext);
  }
}

describe('DPAPI fail-closed agent credential cache', () => {
  it('stores principal, binding, policy, permissions, and TTL in the sealed entry', async () => {
    const now = Date.now();
    const protector = new PlaintextCurrentUserProtector();
    const permissionsHash = computePermissionsHash({ permissions: ['write:credentials'] });
    const cache = new DpapiFailClosedAgentCache(new MemoryAgentCredentialCacheStore(), protector);

    const sealed = await cache.write('agent-a', {
      principalId: 'principal_abc',
      bindingHash: 'sha256:binding-a',
      policyDigest: 'sha256:policy-a',
      permissionsHash,
      expiresAt: now + 60_000,
      credentialMaterial: { kind: 'bpc-device-key', value: 'sealed-only' },
      nowMs: now,
    });

    expect(sealed.scope).toBe('CurrentUser');

    const entry = await cache.read('agent-a', {
      principalId: 'principal_abc',
      bindingHash: 'sha256:binding-a',
      policyDigest: 'sha256:policy-a',
      permissionsHash,
      nowMs: now + 1,
    });

    expect(entry).toMatchObject({
      principal_id: 'principal_abc',
      binding_hash: 'sha256:binding-a',
      policy_digest: 'sha256:policy-a',
      permissions_hash: permissionsHash,
      expires_at: now + 60_000,
    });
  });

  it('throws CacheTamperedError when the sealed binding_hash is changed', async () => {
    const now = Date.now();
    const protector = new PlaintextCurrentUserProtector();
    const permissionsHash = computePermissionsHash({ permissions: ['write:credentials'] });
    const sealed = await sealAgentCredentialCacheEntry({
      principalId: 'principal_abc',
      bindingHash: 'sha256:binding-a',
      policyDigest: 'sha256:policy-a',
      permissionsHash,
      expiresAt: now + 60_000,
      credentialMaterial: 'credential-material',
      nowMs: now,
    }, protector);

    const tampered = tamperSealedEntry(sealed, entry => {
      entry.binding_hash = 'sha256:binding-b';
    });
    const store = new MemoryAgentCredentialCacheStore();
    await store.put('agent-a', tampered);
    const cache = new DpapiFailClosedAgentCache(store, protector);

    await expect(cache.read('agent-a', {
      principalId: 'principal_abc',
      bindingHash: 'sha256:binding-a',
      policyDigest: 'sha256:policy-a',
      permissionsHash,
      nowMs: now + 1,
    })).rejects.toBeInstanceOf(CacheTamperedError);
  });

  it('throws named fail-closed errors for stale policy, invalid scope, expired cache, and missing entries', async () => {
    const now = Date.now();
    const protector = new PlaintextCurrentUserProtector();
    const permissionsHash = computePermissionsHash({ permissions: ['write:credentials'] });
    const store = new MemoryAgentCredentialCacheStore();
    const cache = new DpapiFailClosedAgentCache(store, protector);

    await cache.write('valid-agent', {
      principalId: 'principal_abc',
      bindingHash: 'sha256:binding-a',
      policyDigest: 'sha256:policy-a',
      permissionsHash,
      expiresAt: now + 60_000,
      credentialMaterial: 'credential-material',
      nowMs: now,
    });

    await expect(cache.read('valid-agent', {
      principalId: 'principal_abc',
      bindingHash: 'sha256:binding-a',
      policyDigest: 'sha256:policy-b',
      permissionsHash,
      nowMs: now + 1,
    })).rejects.toBeInstanceOf(CacheTamperedError);

    const scopeTampered = await sealAgentCredentialCacheEntry({
      principalId: 'principal_abc',
      bindingHash: 'sha256:binding-a',
      policyDigest: 'sha256:policy-a',
      permissionsHash,
      expiresAt: now + 60_000,
      credentialMaterial: 'credential-material',
      nowMs: now,
    }, protector);
    await store.put('scope-tampered-agent', {
      ...scopeTampered,
      scope: 'LocalMachine' as 'CurrentUser',
    });

    await expect(cache.read('scope-tampered-agent', {
      principalId: 'principal_abc',
      bindingHash: 'sha256:binding-a',
      policyDigest: 'sha256:policy-a',
      permissionsHash,
      nowMs: now + 1,
    })).rejects.toBeInstanceOf(CacheTamperedError);

    await cache.write('expired-agent', {
      principalId: 'principal_abc',
      bindingHash: 'sha256:binding-a',
      policyDigest: 'sha256:policy-a',
      permissionsHash,
      expiresAt: now - 1,
      credentialMaterial: 'credential-material',
      nowMs: now - 1000,
    });

    await expect(cache.read('expired-agent', {
      principalId: 'principal_abc',
      bindingHash: 'sha256:binding-a',
      policyDigest: 'sha256:policy-a',
      permissionsHash,
      nowMs: now,
    })).rejects.toBeInstanceOf(CacheExpiredError);

    await expect(cache.read('missing-agent', {
      principalId: 'principal_abc',
      bindingHash: 'sha256:binding-a',
      policyDigest: 'sha256:policy-a',
      permissionsHash,
      nowMs: now,
    })).rejects.toBeInstanceOf(CacheUnavailableError);
  });
});

function tamperSealedEntry(
  sealed: SealedAgentCredentialCache,
  mutate: (entry: Record<string, unknown>) => void,
): SealedAgentCredentialCache {
  const entry = JSON.parse(Buffer.from(sealed.ciphertext_b64, 'base64').toString('utf8')) as Record<string, unknown>;
  mutate(entry);
  return {
    ...sealed,
    ciphertext_b64: Buffer.from(JSON.stringify(entry), 'utf8').toString('base64'),
  };
}
