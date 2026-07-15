import { execFile } from 'node:child_process';
import { createHash, timingSafeEqual } from 'node:crypto';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

export type DpapiScope = 'CurrentUser';

export interface DpapiProtector {
  readonly scope: DpapiScope;
  protect(plaintext: Uint8Array): Promise<Uint8Array>;
  unprotect(ciphertext: Uint8Array): Promise<Uint8Array>;
}

export interface AgentCredentialCacheEntry {
  version: '1';
  principal_id: string;
  binding_hash: string;
  policy_digest: string;
  permissions_hash: string;
  expires_at: number;
  sealed_at: number;
  credential_material: unknown;
}

export interface CreateAgentCredentialCacheEntryInput {
  principalId: string;
  bindingHash: string;
  policyDigest: string;
  permissionsHash: string;
  expiresAt: number;
  credentialMaterial: unknown;
  nowMs?: number;
}

export interface SealedAgentCredentialCache {
  version: '1';
  scope: DpapiScope;
  protected_at: number;
  ciphertext_b64: string;
}

export interface AgentCredentialCacheExpectedState {
  principalId: string;
  bindingHash: string;
  policyDigest: string;
  permissionsHash: string;
  nowMs?: number;
}

export interface AgentCredentialCacheStore {
  put(cacheKey: string, cache: SealedAgentCredentialCache): Promise<void>;
  get(cacheKey: string): Promise<SealedAgentCredentialCache | undefined>;
}

export class CacheExpiredError extends Error {
  readonly code = 'CACHE_EXPIRED';

  constructor(message = 'agent credential cache expired') {
    super(message);
    this.name = 'CacheExpiredError';
  }
}

export class CacheTamperedError extends Error {
  readonly code = 'CACHE_TAMPERED';

  constructor(message = 'agent credential cache tampered') {
    super(message);
    this.name = 'CacheTamperedError';
  }
}

export class CacheUnavailableError extends Error {
  readonly code = 'CACHE_UNAVAILABLE';

  constructor(message = 'agent credential cache unavailable') {
    super(message);
    this.name = 'CacheUnavailableError';
  }
}

export class MemoryAgentCredentialCacheStore implements AgentCredentialCacheStore {
  private readonly entries = new Map<string, SealedAgentCredentialCache>();

  async put(cacheKey: string, cache: SealedAgentCredentialCache): Promise<void> {
    this.entries.set(assertCacheKey(cacheKey), cache);
  }

  async get(cacheKey: string): Promise<SealedAgentCredentialCache | undefined> {
    return this.entries.get(assertCacheKey(cacheKey));
  }
}

export class DpapiFailClosedAgentCache {
  constructor(
    private readonly store: AgentCredentialCacheStore,
    private readonly protector: DpapiProtector = new WindowsCurrentUserDpapiProtector(),
  ) {}

  async write(cacheKey: string, input: CreateAgentCredentialCacheEntryInput): Promise<SealedAgentCredentialCache> {
    const sealed = await sealAgentCredentialCacheEntry(input, this.protector);
    await this.store.put(cacheKey, sealed);
    return sealed;
  }

  async read(cacheKey: string, expected: AgentCredentialCacheExpectedState): Promise<AgentCredentialCacheEntry> {
    const sealed = await this.store.get(cacheKey);
    if (!sealed) throw new CacheUnavailableError('agent credential cache entry unavailable');
    return openAgentCredentialCacheEntry({ sealedCache: sealed, expected, protector: this.protector });
  }
}

export interface OpenAgentCredentialCacheEntryInput {
  sealedCache: SealedAgentCredentialCache;
  expected: AgentCredentialCacheExpectedState;
  protector: DpapiProtector;
}

/**
 * Windows DPAPI provider locked to DataProtectionScope.CurrentUser.
 * Do not widen this to machine scope: the cache is only intended to decrypt
 * under the same Windows identity that performed the original binding.
 */
export class WindowsCurrentUserDpapiProtector implements DpapiProtector {
  readonly scope = 'CurrentUser' as const;

  constructor(private readonly powershellPath = 'powershell.exe') {}

  async protect(plaintext: Uint8Array): Promise<Uint8Array> {
    if (process.platform !== 'win32') {
      throw new CacheUnavailableError('DPAPI CurrentUser protection is only available on Windows');
    }

    try {
      return await this.runDpapi('protect', plaintext);
    } catch (error) {
      if (error instanceof CacheUnavailableError) throw error;
      throw new CacheUnavailableError('DPAPI CurrentUser protection failed');
    }
  }

  async unprotect(ciphertext: Uint8Array): Promise<Uint8Array> {
    if (process.platform !== 'win32') {
      throw new CacheUnavailableError('DPAPI CurrentUser protection is only available on Windows');
    }

    try {
      return await this.runDpapi('unprotect', ciphertext);
    } catch (error) {
      if (error instanceof CacheUnavailableError || error instanceof CacheTamperedError) throw error;
      throw new CacheTamperedError('DPAPI CurrentUser cache could not be unsealed');
    }
  }

  private async runDpapi(operation: 'protect' | 'unprotect', input: Uint8Array): Promise<Uint8Array> {
    const inputB64 = Buffer.from(input).toString('base64');
    const script = [
      '$ErrorActionPreference = "Stop";',
      'Add-Type -AssemblyName System.Security;',
      `$operation = '${operation}';`,
      `$inputB64 = '${inputB64}';`,
      '$bytes = [Convert]::FromBase64String($inputB64);',
      '$scope = [System.Security.Cryptography.DataProtectionScope]::CurrentUser;',
      'if ($operation -eq "protect") {',
      '  $out = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, $scope);',
      '} elseif ($operation -eq "unprotect") {',
      '  $out = [System.Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, $scope);',
      '} else {',
      '  throw "unknown DPAPI operation";',
      '}',
      '[Convert]::ToBase64String($out)',
    ].join(' ');
    const encodedCommand = Buffer.from(script, 'utf16le').toString('base64');

    const { stdout } = await execFileAsync(
      this.powershellPath,
      [
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy',
        'Bypass',
        '-EncodedCommand',
        encodedCommand,
      ],
      { windowsHide: true, maxBuffer: 1024 * 1024 },
    );

    const output = String(stdout).trim();
    if (!output) throw new CacheUnavailableError('DPAPI returned no output');
    return Buffer.from(output, 'base64');
  }
}

export async function sealAgentCredentialCacheEntry(
  input: CreateAgentCredentialCacheEntryInput,
  protector: DpapiProtector = new WindowsCurrentUserDpapiProtector(),
): Promise<SealedAgentCredentialCache> {
  if (protector.scope !== 'CurrentUser') {
    throw new CacheUnavailableError('agent credential cache requires DPAPI CurrentUser scope');
  }

  const entry = createAgentCredentialCacheEntry(input);
  const plaintext = Buffer.from(JSON.stringify(entry), 'utf8');
  const ciphertext = await protector.protect(plaintext);

  return {
    version: '1',
    scope: 'CurrentUser',
    protected_at: entry.sealed_at,
    ciphertext_b64: Buffer.from(ciphertext).toString('base64'),
  };
}

export async function openAgentCredentialCacheEntry(
  input: OpenAgentCredentialCacheEntryInput,
): Promise<AgentCredentialCacheEntry> {
  validateSealedEnvelope(input.sealedCache);
  if (input.protector.scope !== 'CurrentUser') {
    throw new CacheUnavailableError('agent credential cache requires DPAPI CurrentUser scope');
  }

  let plaintext: Uint8Array;
  try {
    plaintext = await input.protector.unprotect(Buffer.from(input.sealedCache.ciphertext_b64, 'base64'));
  } catch (error) {
    if (
      error instanceof CacheExpiredError ||
      error instanceof CacheTamperedError ||
      error instanceof CacheUnavailableError
    ) {
      throw error;
    }
    throw new CacheTamperedError('agent credential cache could not be unsealed');
  }

  const entry = parseCacheEntry(Buffer.from(plaintext).toString('utf8'));
  validateEntryAgainstCurrentState(entry, input.expected);
  return entry;
}

export function createAgentCredentialCacheEntry(input: CreateAgentCredentialCacheEntryInput): AgentCredentialCacheEntry {
  const now = input.nowMs ?? Date.now();
  const entry: AgentCredentialCacheEntry = {
    version: '1',
    principal_id: requireNonEmptyString(input.principalId, 'principalId'),
    binding_hash: requireNonEmptyString(input.bindingHash, 'bindingHash'),
    policy_digest: requireNonEmptyString(input.policyDigest, 'policyDigest'),
    permissions_hash: requireNonEmptyString(input.permissionsHash, 'permissionsHash'),
    expires_at: requireFiniteTimestamp(input.expiresAt, 'expiresAt'),
    sealed_at: requireFiniteTimestamp(now, 'nowMs'),
    credential_material: input.credentialMaterial,
  };

  if (!Object.prototype.hasOwnProperty.call(input, 'credentialMaterial')) {
    throw new CacheTamperedError('agent credential cache entry missing credential material');
  }
  return entry;
}

export function computePermissionsHash(authorizationContext: unknown): string {
  return `sha256:${sha256hex(canonicalJson(authorizationContext))}`;
}

function validateEntryAgainstCurrentState(
  entry: AgentCredentialCacheEntry,
  expected: AgentCredentialCacheExpectedState,
): void {
  const now = expected.nowMs ?? Date.now();
  if (entry.expires_at <= now) throw new CacheExpiredError();

  assertSameField(entry.principal_id, expected.principalId, 'principal_id');
  assertSameField(entry.binding_hash, expected.bindingHash, 'binding_hash');
  assertSameField(entry.policy_digest, expected.policyDigest, 'policy_digest');
  assertSameField(entry.permissions_hash, expected.permissionsHash, 'permissions_hash');
}

function validateSealedEnvelope(cache: SealedAgentCredentialCache): void {
  if (!cache || typeof cache !== 'object') throw new CacheTamperedError('agent credential cache envelope invalid');
  if (cache.version !== '1') throw new CacheTamperedError('agent credential cache version invalid');
  if (cache.scope !== 'CurrentUser') throw new CacheTamperedError('agent credential cache scope invalid');
  requireNonEmptyString(cache.ciphertext_b64, 'ciphertext_b64');
  requireFiniteTimestamp(cache.protected_at, 'protected_at');
}

function parseCacheEntry(serialized: string): AgentCredentialCacheEntry {
  let parsed: unknown;
  try {
    parsed = JSON.parse(serialized);
  } catch {
    throw new CacheTamperedError('agent credential cache payload is not valid JSON');
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new CacheTamperedError('agent credential cache payload invalid');
  }

  const record = parsed as Partial<AgentCredentialCacheEntry>;
  const entry: AgentCredentialCacheEntry = {
    version: record.version as '1',
    principal_id: requireNonEmptyString(record.principal_id, 'principal_id'),
    binding_hash: requireNonEmptyString(record.binding_hash, 'binding_hash'),
    policy_digest: requireNonEmptyString(record.policy_digest, 'policy_digest'),
    permissions_hash: requireNonEmptyString(record.permissions_hash, 'permissions_hash'),
    expires_at: requireFiniteTimestamp(record.expires_at, 'expires_at'),
    sealed_at: requireFiniteTimestamp(record.sealed_at, 'sealed_at'),
    credential_material: record.credential_material,
  };

  if (entry.version !== '1') throw new CacheTamperedError('agent credential cache payload version invalid');
  if (!Object.prototype.hasOwnProperty.call(record, 'credential_material')) {
    throw new CacheTamperedError('agent credential cache payload missing credential material');
  }
  return entry;
}

function assertSameField(actual: string, expected: string, fieldName: string): void {
  if (!constantTimeStringEqual(actual, requireNonEmptyString(expected, fieldName))) {
    throw new CacheTamperedError(`agent credential cache ${fieldName} mismatch`);
  }
}

function constantTimeStringEqual(a: string, b: string): boolean {
  const aHash = createHash('sha256').update(a, 'utf8').digest();
  const bHash = createHash('sha256').update(b, 'utf8').digest();
  return timingSafeEqual(aHash, bHash);
}

function requireNonEmptyString(value: unknown, fieldName: string): string {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new CacheTamperedError(`agent credential cache ${fieldName} invalid`);
  }
  return value;
}

function requireFiniteTimestamp(value: unknown, fieldName: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new CacheTamperedError(`agent credential cache ${fieldName} invalid`);
  }
  return value;
}

function assertCacheKey(cacheKey: string): string {
  if (!cacheKey || cacheKey.trim() === '') throw new CacheUnavailableError('agent credential cache key is required');
  return cacheKey;
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
