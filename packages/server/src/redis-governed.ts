/**
 * Governed Redis replay protection.
 *
 * Continuity state, shared quarantine, and each nonce live in one Redis
 * Cluster hash slot. The nonce EVAL validates continuity and consumes the
 * nonce atomically; a local preflight is only an optimization.
 */

import { randomUUID } from 'node:crypto';

import type { Redis } from 'ioredis';

import type { NonceStoreBackend } from './store.js';
import { NonceStoreUnavailableError, ServerNonceStore } from './nonce-store.js';
import {
  AuthorizationQuarantineError,
  DEFAULT_CONTINUITY_SAFETY_ALLOWANCE_MS,
  type ContinuityGate,
  type RedisConfigClient,
  assertNoEvictionPolicy,
  startContinuityReconcileLoop,
} from './redis-continuity.js';
import {
  DEFAULT_REDIS_NONCE_TIMEOUT_MS,
  deriveNonceRetentionMs,
  type RedisBackedNonceOptions,
  type RedisBackedNonceStore,
} from './redis-nonce.js';

export interface RedisAtomicClient extends RedisConfigClient {
  eval(
    script: string | Buffer,
    numKeys: number | string,
    ...args: Array<string | Buffer | number>
  ): Promise<unknown>;
}

// This is an executable compile contract: the exact peer dependency used by
// the repository must remain structurally assignable to the public interface.
type Assert<T extends true> = T;
type IORedisCompileContract = Assert<Redis extends RedisAtomicClient ? true : false>;
type _KeepCompileContract = IORedisCompileContract;

export interface GovernedRedisBackedNonceOptions extends Omit<RedisBackedNonceOptions, 'continuityMode'> {
  /** Extra shared quarantine beyond nonce retention. Default: 30 seconds. */
  continuitySafetyAllowanceMs?: number;
  /** Reconcile cadence. Must be shorter than retention. Default: <= 5 seconds. */
  reconcileIntervalMs?: number;
  /** Optional externally checkpointed epoch. A mismatch enters shared quarantine. */
  expectedEpoch?: string;
  /** Operational observer; observer failures are contained. */
  onReconcileError?: (error: unknown) => void;
  /** Testable epoch source. Defaults to crypto.randomUUID(). */
  newEpoch?: () => string;
}

export interface GovernedRedisBackedNonceStore extends RedisBackedNonceStore {
  readonly continuityKey: string;
  readonly quarantineKey: string;
  readonly continuityConfigKey: string;
  readonly continuityGuard: ContinuityGate;
  readonly continuityEpoch: string;
  readonly verifierConfig: {
    readonly sigWindowMs: number;
    readonly continuityGuard: ContinuityGate;
  };
  stop(): Promise<void>;
}

export class RedisContinuityConfigurationError extends Error {
  readonly code = 'redis_continuity_config_mismatch';
  constructor(readonly status: 'CONFIG_MISMATCH' | 'CONFIG_INVALID') {
    super(`Redis continuity configuration rejected (${status})`);
    this.name = 'RedisContinuityConfigurationError';
  }
}

const RECONCILE_SCRIPT = String.raw`
local quarantine_ms = tonumber(ARGV[2])
if not quarantine_ms or quarantine_ms <= 0 then
  return {'INVALID', '', '-2'}
end

local function quarantine_at_least(epoch, minimum_ms)
  local ttl = redis.call('PTTL', KEYS[2])
  local duration = minimum_ms
  if ttl > duration then duration = ttl end
  redis.call('SET', KEYS[2], epoch, 'PX', duration)
  return redis.call('PTTL', KEYS[2])
end

local epoch = redis.call('GET', KEYS[1])
local config = redis.call('GET', KEYS[3])
local status = 'OK'
if not config then
  quarantine_at_least(epoch or ARGV[1], quarantine_ms)
  redis.call('SET', KEYS[3], ARGV[4], 'NX')
  config = redis.call('GET', KEYS[3])
  status = 'CONFIG_ESTABLISHED'
end

local stored_retention, stored_quarantine = string.match(config or '', '^(%d+):(%d+)$')
stored_retention = tonumber(stored_retention)
stored_quarantine = tonumber(stored_quarantine)
if not stored_retention or stored_retention <= 0 or not stored_quarantine or stored_quarantine <= 0 then
  local ttl = quarantine_at_least(epoch or ARGV[1], quarantine_ms)
  return {'CONFIG_INVALID', epoch or ARGV[1], tostring(ttl)}
end
if config ~= ARGV[4] then
  local minimum = quarantine_ms
  if stored_quarantine > minimum then minimum = stored_quarantine end
  local ttl = quarantine_at_least(epoch or ARGV[1], minimum)
  return {'CONFIG_MISMATCH', epoch or ARGV[1], tostring(ttl)}
end

if not epoch then
  -- Quarantine first. Redis scripts are isolated but are not transactional
  -- rollbacks after runtime/server failures.
  quarantine_at_least(ARGV[1], quarantine_ms)
  redis.call('SET', KEYS[1], ARGV[1], 'NX')
  epoch = redis.call('GET', KEYS[1])
  if not epoch then
    return {'INVALID', '', tostring(redis.call('PTTL', KEYS[2]))}
  end
  status = 'MISSING'
end

if ARGV[3] ~= '' and epoch ~= ARGV[3] then
  quarantine_at_least(epoch, quarantine_ms)
  status = 'EPOCH_CHANGED'
end

local quarantine = redis.call('GET', KEYS[2])
local ttl = redis.call('PTTL', KEYS[2])
if quarantine and (quarantine ~= epoch or ttl <= 0) then
  ttl = quarantine_at_least(epoch, quarantine_ms)
end
return {status, epoch, tostring(ttl)}
`;

const CONSUME_SCRIPT = String.raw`
local quarantine_ms = tonumber(ARGV[3])
if not quarantine_ms or quarantine_ms <= 0 then
  return {'INVALID', '', '-2'}
end

local function quarantine_at_least(epoch, minimum_ms)
  local ttl = redis.call('PTTL', KEYS[2])
  local duration = minimum_ms
  if ttl > duration then duration = ttl end
  redis.call('SET', KEYS[2], epoch, 'PX', duration)
  return redis.call('PTTL', KEYS[2])
end

local epoch = redis.call('GET', KEYS[1])
local config = redis.call('GET', KEYS[3])
if not config then
  local ttl = quarantine_at_least(epoch or ARGV[2], quarantine_ms)
  redis.call('SET', KEYS[3], ARGV[5], 'NX')
  return {'CONFIG_MISSING', epoch or ARGV[2], tostring(ttl)}
end
local stored_retention, stored_quarantine = string.match(config, '^(%d+):(%d+)$')
stored_retention = tonumber(stored_retention)
stored_quarantine = tonumber(stored_quarantine)
if not stored_retention or stored_retention <= 0 or not stored_quarantine or stored_quarantine <= 0 then
  local ttl = quarantine_at_least(epoch or ARGV[2], quarantine_ms)
  return {'CONFIG_INVALID', epoch or ARGV[2], tostring(ttl)}
end
if config ~= ARGV[5] then
  local minimum = quarantine_ms
  if stored_quarantine > minimum then minimum = stored_quarantine end
  local ttl = quarantine_at_least(epoch or ARGV[2], minimum)
  return {'CONFIG_MISMATCH', epoch or ARGV[2], tostring(ttl)}
end

if not epoch then
  -- Establish shared quarantine before exposing a replacement epoch.
  quarantine_at_least(ARGV[2], quarantine_ms)
  redis.call('SET', KEYS[1], ARGV[2], 'NX')
  epoch = redis.call('GET', KEYS[1])
  return {'MISSING', epoch or '', tostring(redis.call('PTTL', KEYS[2]))}
end

if epoch ~= ARGV[1] then
  local ttl = quarantine_at_least(epoch, quarantine_ms)
  return {'EPOCH_CHANGED', epoch, tostring(ttl)}
end

local quarantine = redis.call('GET', KEYS[2])
if quarantine then
  local ttl = redis.call('PTTL', KEYS[2])
  if quarantine ~= epoch or ttl <= 0 then
    ttl = quarantine_at_least(epoch, quarantine_ms)
    return {'MALFORMED', epoch, tostring(ttl)}
  end
  return {'QUARANTINED', epoch, tostring(ttl)}
end

local result = redis.call('SET', KEYS[4], '1', 'NX', 'PX', ARGV[4])
if result then
  return {'FRESH', epoch, '-2'}
end
return {'REPLAY', epoch, '-2'}
`;

function positiveSafeInteger(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new RangeError(`${label} must be a positive safe integer`);
  }
  return value;
}

function nonNegativeSafeInteger(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RangeError(`${label} must be a non-negative safe integer`);
  }
  return value;
}

function validateEpoch(epoch: string, label: string): string {
  if (!/^[A-Za-z0-9._-]{1,128}$/.test(epoch)) {
    throw new RangeError(`${label} must be 1-128 ASCII letters, digits, dot, underscore, or hyphen`);
  }
  return epoch;
}

async function withTimeout<T>(operation: Promise<T>, timeoutMs: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () => reject(new NonceStoreUnavailableError(new Error('Redis governed command timed out'))),
      timeoutMs,
    );
  });
  try {
    return await Promise.race([operation, timeout]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

function parseReply(raw: unknown): [status: string, epoch: string, ttlMs: number] {
  if (
    !Array.isArray(raw)
    || raw.length !== 3
    || typeof raw[0] !== 'string'
    || typeof raw[1] !== 'string'
    || (typeof raw[2] !== 'string' && typeof raw[2] !== 'number')
  ) {
    throw new NonceStoreUnavailableError(new Error('Redis governed script returned an invalid response'));
  }
  const ttlMs = Number(raw[2]);
  if (!Number.isSafeInteger(ttlMs) || ttlMs < -2) {
    throw new NonceStoreUnavailableError(new Error('Redis governed script returned an invalid TTL'));
  }
  return [raw[0], raw[1], ttlMs];
}

class SharedContinuityGate implements ContinuityGate {
  private epoch: string | null = null;
  private quarantinedUntilMs = Number.POSITIVE_INFINITY;
  private reason: AuthorizationQuarantineError['reason'] = 'continuity_store_unavailable';
  private stopped = false;

  constructor(private readonly now: () => number) {}

  get continuityEpoch(): string {
    if (this.epoch === null) throw new AuthorizationQuarantineError(this.reason, this.quarantinedUntilMs);
    return this.epoch;
  }

  expectedEpoch(): string {
    this.assertAcceptable();
    return this.continuityEpoch;
  }

  apply(epoch: string, ttlMs: number, reason?: AuthorizationQuarantineError['reason']): void {
    validateEpoch(epoch, 'Redis continuity epoch');
    if (this.stopped) return;
    this.epoch = epoch;
    this.reason = reason ?? 'continuity_marker_lost';
    this.quarantinedUntilMs = ttlMs > 0 ? this.now() + ttlMs : 0;
  }

  failClosed(reason: AuthorizationQuarantineError['reason'] = 'continuity_store_unavailable'): void {
    this.reason = reason;
    this.quarantinedUntilMs = Number.POSITIVE_INFINITY;
  }

  close(): void {
    this.stopped = true;
    this.failClosed('continuity_store_unavailable');
  }

  assertAcceptable(nowMs = this.now()): void {
    if (this.stopped || this.epoch === null || nowMs < this.quarantinedUntilMs) {
      throw new AuthorizationQuarantineError(this.reason, this.quarantinedUntilMs);
    }
  }
}

class AtomicContinuityNonceStore implements NonceStoreBackend {
  constructor(
    private readonly redis: RedisAtomicClient,
    private readonly gate: SharedContinuityGate,
    private readonly continuityKey: string,
    private readonly quarantineKey: string,
    private readonly continuityConfigKey: string,
    private readonly noncePrefix: string,
    private readonly continuityConfig: string,
    private readonly quarantineMs: number,
    private readonly commandTimeoutMs: number,
    private readonly newEpoch: () => string,
  ) {}

  async checkAndConsume(nonce: string, ttlMs: number): Promise<boolean> {
    positiveSafeInteger(ttlMs, 'ttlMs');
    const expectedEpoch = this.gate.expectedEpoch();
    const replacementEpoch = validateEpoch(this.newEpoch(), 'newEpoch() result');
    try {
      const raw = await withTimeout(
        this.redis.eval(
          CONSUME_SCRIPT,
          4,
          this.continuityKey,
          this.quarantineKey,
          this.continuityConfigKey,
          this.noncePrefix + nonce,
          expectedEpoch,
          replacementEpoch,
          this.quarantineMs,
          ttlMs,
          this.continuityConfig,
        ),
        this.commandTimeoutMs,
      );
      const [status, epoch, quarantineTtlMs] = parseReply(raw);
      if (status === 'FRESH' || status === 'REPLAY') {
        if (epoch !== expectedEpoch || quarantineTtlMs !== -2) {
          throw new NonceStoreUnavailableError(
            new Error(`Redis governed ${status} response violated epoch/TTL invariants`),
          );
        }
        return status === 'REPLAY';
      }
      if ([
        'MISSING',
        'EPOCH_CHANGED',
        'MALFORMED',
        'QUARANTINED',
        'CONFIG_MISSING',
        'CONFIG_MISMATCH',
        'CONFIG_INVALID',
      ].includes(status)) {
        validateEpoch(epoch, `Redis governed ${status} epoch`);
        if (quarantineTtlMs <= 0) {
          throw new NonceStoreUnavailableError(
            new Error(`Redis governed ${status} response lacked a positive quarantine TTL`),
          );
        }
        const reason = status === 'EPOCH_CHANGED'
          ? 'continuity_epoch_changed'
          : status.startsWith('CONFIG_')
            ? 'continuity_config_mismatch'
            : 'continuity_marker_lost';
        this.gate.apply(epoch, quarantineTtlMs, reason);
        throw new AuthorizationQuarantineError(reason, Date.now() + quarantineTtlMs);
      }
      throw new NonceStoreUnavailableError(new Error(`Unknown governed Redis status: ${status}`));
    } catch (error) {
      if (error instanceof AuthorizationQuarantineError) throw error;
      this.gate.failClosed();
      if (error instanceof NonceStoreUnavailableError) throw error;
      throw new NonceStoreUnavailableError(error);
    }
  }
}

export async function createGovernedRedisBackedNonceStore(
  redis: RedisAtomicClient,
  options: GovernedRedisBackedNonceOptions,
): Promise<GovernedRedisBackedNonceStore> {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(options.namespace)) {
    throw new RangeError('namespace must be 1-64 ASCII letters, digits, dot, underscore, or hyphen');
  }
  const retentionMs = deriveNonceRetentionMs(options.sigWindowMs, options.safetyBufferMs);
  const allowanceMs = nonNegativeSafeInteger(
    options.continuitySafetyAllowanceMs ?? DEFAULT_CONTINUITY_SAFETY_ALLOWANCE_MS,
    'continuitySafetyAllowanceMs',
  );
  const quarantineMs = positiveSafeInteger(retentionMs + allowanceMs, 'quarantineMs');
  const commandTimeoutMs = positiveSafeInteger(
    options.commandTimeoutMs ?? DEFAULT_REDIS_NONCE_TIMEOUT_MS,
    'commandTimeoutMs',
  );
  const intervalMs = positiveSafeInteger(
    options.reconcileIntervalMs ?? Math.min(5_000, Math.max(1, Math.floor(retentionMs / 2))),
    'reconcileIntervalMs',
  );
  if (intervalMs >= retentionMs) {
    throw new RangeError('reconcileIntervalMs must be shorter than nonce retentionMs');
  }
  const makeEpoch = options.newEpoch ?? randomUUID;
  const initialEpoch = validateEpoch(makeEpoch(), 'newEpoch() result');
  const expectedEpoch = options.expectedEpoch === undefined
    ? ''
    : validateEpoch(options.expectedEpoch, 'expectedEpoch');
  const tag = `{${options.namespace}}`;
  const continuityKey = `bpc:${tag}:continuity:v2`;
  const quarantineKey = `bpc:${tag}:continuity-quarantine:v2`;
  const continuityConfigKey = `bpc:${tag}:continuity-config:v2`;
  const keyPrefix = `bpc:${tag}:nonce:`;
  const continuityConfig = `${retentionMs}:${quarantineMs}`;
  const gate = new SharedContinuityGate(Date.now);

  const reconcile = async (): Promise<void> => {
    try {
      await withTimeout(assertNoEvictionPolicy(redis), commandTimeoutMs);
      const reconcileExpectedEpoch = gate.continuityEpoch;
      const raw = await withTimeout(
        redis.eval(
          RECONCILE_SCRIPT,
          3,
          continuityKey,
          quarantineKey,
          continuityConfigKey,
          validateEpoch(makeEpoch(), 'newEpoch() result'),
          quarantineMs,
          reconcileExpectedEpoch,
          continuityConfig,
        ),
        commandTimeoutMs,
      );
      const [status, epoch, ttlMs] = parseReply(raw);
      if (status === 'CONFIG_MISMATCH' || status === 'CONFIG_INVALID') {
        throw new RedisContinuityConfigurationError(status);
      }
      if (!['OK', 'CONFIG_ESTABLISHED', 'MISSING', 'EPOCH_CHANGED'].includes(status)) {
        throw new Error(`Unknown continuity reconcile status: ${status}`);
      }
      validateEpoch(epoch, `Redis continuity ${status} epoch`);
      const establishesQuarantine = status !== 'OK';
      if ((establishesQuarantine && ttlMs <= 0) || (!establishesQuarantine && ttlMs !== -2 && ttlMs <= 0)) {
        throw new Error(`Redis continuity ${status} response had an invalid quarantine TTL`);
      }
      if (
        (status === 'OK' || status === 'CONFIG_ESTABLISHED')
          && epoch !== reconcileExpectedEpoch
      ) {
        throw new Error(`Redis continuity ${status} response violated the expected epoch`);
      }
      if (status === 'EPOCH_CHANGED' && epoch === reconcileExpectedEpoch) {
        throw new Error('Redis continuity EPOCH_CHANGED response retained the expected epoch');
      }
      const reason: AuthorizationQuarantineError['reason'] = status === 'EPOCH_CHANGED'
        ? 'continuity_epoch_changed'
        : status === 'CONFIG_ESTABLISHED'
          ? 'continuity_config_mismatch'
          : 'continuity_marker_lost';
      gate.apply(epoch, ttlMs, reason);
    } catch (error) {
      gate.failClosed();
      throw error;
    }
  };

  await withTimeout(assertNoEvictionPolicy(redis), commandTimeoutMs);
  const bootstrapRaw = await withTimeout(
    redis.eval(
      RECONCILE_SCRIPT,
      3,
      continuityKey,
      quarantineKey,
      continuityConfigKey,
      initialEpoch,
      quarantineMs,
      expectedEpoch,
      continuityConfig,
    ),
    commandTimeoutMs,
  );
  const [bootstrapStatus, bootstrapEpoch, bootstrapTtlMs] = parseReply(bootstrapRaw);
  if (bootstrapStatus === 'CONFIG_MISMATCH' || bootstrapStatus === 'CONFIG_INVALID') {
    throw new RedisContinuityConfigurationError(bootstrapStatus);
  }
  if (!['OK', 'CONFIG_ESTABLISHED', 'MISSING', 'EPOCH_CHANGED'].includes(bootstrapStatus)) {
    throw new NonceStoreUnavailableError(new Error(`Unknown continuity bootstrap status: ${bootstrapStatus}`));
  }
  validateEpoch(bootstrapEpoch, `Redis continuity ${bootstrapStatus} epoch`);
  const bootstrapEstablishesQuarantine = bootstrapStatus !== 'OK';
  if (
    (bootstrapEstablishesQuarantine && bootstrapTtlMs <= 0)
    || (!bootstrapEstablishesQuarantine && bootstrapTtlMs !== -2 && bootstrapTtlMs <= 0)
  ) {
    throw new NonceStoreUnavailableError(
      new Error(`Redis continuity ${bootstrapStatus} response had an invalid quarantine TTL`),
    );
  }
  if (
    expectedEpoch !== ''
    && (bootstrapStatus === 'OK' || bootstrapStatus === 'CONFIG_ESTABLISHED')
    && bootstrapEpoch !== expectedEpoch
  ) {
    throw new NonceStoreUnavailableError(
      new Error(`Redis continuity ${bootstrapStatus} response violated the expected epoch`),
    );
  }
  if (
    bootstrapStatus === 'EPOCH_CHANGED'
    && (expectedEpoch === '' || bootstrapEpoch === expectedEpoch)
  ) {
    throw new NonceStoreUnavailableError(
      new Error('Redis continuity EPOCH_CHANGED response violated bootstrap invariants'),
    );
  }
  const bootstrapReason: AuthorizationQuarantineError['reason'] = bootstrapStatus === 'EPOCH_CHANGED'
    ? 'continuity_epoch_changed'
    : bootstrapStatus === 'CONFIG_ESTABLISHED'
      ? 'continuity_config_mismatch'
      : 'continuity_marker_lost';
  gate.apply(
    bootstrapEpoch,
    bootstrapTtlMs,
    bootstrapReason,
  );

  const backend = new AtomicContinuityNonceStore(
    redis,
    gate,
    continuityKey,
    quarantineKey,
    continuityConfigKey,
    keyPrefix,
    continuityConfig,
    quarantineMs,
    commandTimeoutMs,
    makeEpoch,
  );
  const nonceStore = new ServerNonceStore(backend, retentionMs);
  const loop = startContinuityReconcileLoop({ reconcile }, {
    intervalMs,
    retentionMs,
    onError: options.onReconcileError,
  });
  let stopPromise: Promise<void> | undefined;
  const verifierConfig = Object.freeze({
    sigWindowMs: options.sigWindowMs,
    continuityGuard: gate as ContinuityGate,
  });

  return {
    nonceStore,
    retentionMs,
    keyPrefix,
    continuityKey,
    quarantineKey,
    continuityConfigKey,
    continuityGuard: gate,
    get continuityEpoch(): string {
      return gate.continuityEpoch;
    },
    verifierConfig,
    stop(): Promise<void> {
      if (stopPromise === undefined) {
        stopPromise = (async () => {
          gate.close();
          await loop.stop();
          gate.close();
        })();
      }
      return stopPromise;
    },
  };
}
