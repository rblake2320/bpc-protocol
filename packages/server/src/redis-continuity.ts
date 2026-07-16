/**
 * Redis continuity guard — issue #11.
 *
 * The Redis nonce store (redis-nonce.ts) proves single-use within a *live*
 * key space. It cannot, by itself, detect that the key space was LOST or
 * SWAPPED: after FLUSHALL, eviction, a restore from an older snapshot, a
 * restart with an empty DB, or an ambiguous failover to a replica missing
 * recent writes, `SET key NX` succeeds for a nonce that was already consumed,
 * so a replay is accepted.
 *
 * This guard binds authorization to a continuity marker persisted
 * independently of ordinary nonce keys. When the marker is absent (state
 * loss) or carries a different epoch than last trusted (failover/restore to
 * another instance), the guard enters an authorization QUARANTINE for at
 * least the full nonce acceptance horizon plus a safety allowance — the
 * span after which every pre-loss nonce has certainly expired and can no
 * longer be replayed. During quarantine, authorization fails closed; the
 * uncertainty never degrades to acceptance.
 *
 * RESIDUAL (must be closed by deployment config, not by this guard):
 * This detects TOTAL loss (flush / restart-empty / restore-from-empty) and
 * failover/restore to another instance (epoch change). It does NOT detect
 * SELECTIVE eviction — a `maxmemory-policy` of `volatile-*`/`allkeys-lru`
 * can evict individual TTL'd nonce keys under memory pressure while the
 * no-TTL marker survives, silently reopening a replay window with the marker
 * still "intact". Redis MUST therefore run with `maxmemory-policy noeviction`
 * so that memory pressure rejects writes (the nonce SET then fails and the
 * existing single-command fail-closed path in redis-nonce.ts triggers)
 * rather than silently dropping nonces. Enforcing that policy from the
 * client is out of scope for the smallest fix and is tracked as follow-up.
 */

export class AuthorizationQuarantineError extends Error {
  readonly code = 'authorization_quarantined';
  constructor(
    readonly reason: 'continuity_marker_lost' | 'continuity_epoch_changed' | 'continuity_store_unavailable',
    readonly quarantinedUntilMs: number,
  ) {
    super(`Authorization quarantined (${reason}) until ${quarantinedUntilMs}`);
    this.name = 'AuthorizationQuarantineError';
  }
}

/** Minimal Redis surface the guard needs. Marker key carries no TTL. */
export interface RedisContinuityClient {
  /** GET marker value, or null if absent. */
  get(key: string): Promise<string | null>;
  /** SET marker only if absent (claims a fresh epoch). Returns 'OK' or null. */
  set(key: string, value: string, nx: 'NX'): Promise<'OK' | null>;
}

/**
 * The gate the verifier request path depends on: assert authorization is
 * currently acceptable, throwing while quarantined. RedisContinuityGuard
 * implements this; middleware only needs this narrow surface.
 */
export interface ContinuityGate {
  assertAcceptable(nowMs?: number): void;
}

/** Redis surface for reading the eviction policy at startup. */
export interface RedisConfigClient {
  /** CONFIG GET parameter -> ['maxmemory-policy', '<value>'] or a map. */
  config(op: 'GET', parameter: string): Promise<string[] | Record<string, string>>;
}

export class EvictionPolicyError extends Error {
  readonly code = 'redis_eviction_policy_unsafe';
  constructor(readonly policy: string) {
    super(
      `Redis maxmemory-policy is '${policy}'; BPC requires 'noeviction' so memory ` +
      `pressure rejects writes instead of silently evicting nonce keys (issue #11/#13).`,
    );
    this.name = 'EvictionPolicyError';
  }
}

/**
 * Assert Redis will not evict keys under memory pressure. Any policy other
 * than 'noeviction' can drop TTL'd nonce keys while the no-TTL continuity
 * marker survives, reopening a replay window the marker cannot detect. Call
 * this when constructing a Redis-backed verifier; it throws EvictionPolicyError
 * on an unsafe policy and fails closed (rethrows) if the policy cannot be read.
 */
export async function assertNoEvictionPolicy(redis: RedisConfigClient): Promise<void> {
  let policy: string | undefined;
  const raw = await redis.config('GET', 'maxmemory-policy');
  if (Array.isArray(raw)) {
    // ioredis returns ['maxmemory-policy', '<value>']
    const idx = raw.indexOf('maxmemory-policy');
    policy = idx >= 0 ? raw[idx + 1] : raw[1];
  } else if (raw && typeof raw === 'object') {
    policy = raw['maxmemory-policy'];
  }
  if (typeof policy !== 'string' || policy.length === 0) {
    throw new EvictionPolicyError('unknown');
  }
  if (policy !== 'noeviction') {
    throw new EvictionPolicyError(policy);
  }
}

/** Stop handle for a periodic reconcile loop. */
export interface ReconcileLoopHandle {
  stop(): void;
}

/**
 * Start a periodic reconcile so mid-run state loss / failover is detected
 * between requests, not only at boot. The interval MUST be shorter than the
 * nonce acceptance horizon so a loss cannot pass unnoticed within one window.
 * Reconcile errors are swallowed here because reconcile() itself fails closed
 * (it quarantines on any store error); the loop must not crash the process.
 */
export function startContinuityReconcileLoop(
  guard: { reconcile(): Promise<void> },
  intervalMs: number,
  onError?: (err: unknown) => void,
): ReconcileLoopHandle {
  if (!Number.isSafeInteger(intervalMs) || intervalMs <= 0) {
    throw new RangeError('intervalMs must be a positive safe integer');
  }
  const timer = setInterval(() => {
    void guard.reconcile().catch((err) => onError?.(err));
  }, intervalMs);
  // Do not keep the event loop alive solely for this tick.
  (timer as { unref?: () => void }).unref?.();
  return { stop: () => clearInterval(timer) };
}

export interface RedisContinuityOptions {
  /** Isolates the marker by deployment/environment. */
  namespace: string;
  /** Nonce acceptance horizon (must match the store's retentionMs). */
  retentionMs: number;
  /** Extra dwell beyond the horizon before trusting again. Default 30s. */
  safetyAllowanceMs?: number;
  /** Command timeout before failing closed. Default 2s. */
  commandTimeoutMs?: number;
  /** Injected clock (ms). Defaults to Date.now. */
  now?: () => number;
  /** Injected epoch token factory (must be unique per instance/boot). */
  newEpoch?: () => string;
}

export const DEFAULT_CONTINUITY_SAFETY_ALLOWANCE_MS = 30_000;
export const DEFAULT_CONTINUITY_TIMEOUT_MS = 2_000;

const NAMESPACE_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

function positiveSafeInteger(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new RangeError(`${label} must be a positive safe integer`);
  }
  return value;
}

async function withTimeout<T>(op: Promise<T>, timeoutMs: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error('continuity command timed out')), timeoutMs);
  });
  try {
    return await Promise.race([op, timeout]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

export class RedisContinuityGuard {
  private readonly markerKey: string;
  private readonly quarantineMs: number;
  private readonly commandTimeoutMs: number;
  private readonly now: () => number;
  private readonly newEpoch: () => string;

  /** Epoch this process trusts; null until first successful establish. */
  private trustedEpoch: string | null = null;
  /** now() < this ⇒ authorization is quarantined (fail closed). */
  private quarantinedUntilMs = 0;

  constructor(
    private readonly redis: RedisContinuityClient,
    options: RedisContinuityOptions,
  ) {
    if (!NAMESPACE_RE.test(options.namespace)) {
      throw new RangeError('namespace must be 1-64 ASCII letters, digits, dot, underscore, or hyphen');
    }
    positiveSafeInteger(options.retentionMs, 'retentionMs');
    const allowance = options.safetyAllowanceMs ?? DEFAULT_CONTINUITY_SAFETY_ALLOWANCE_MS;
    if (!Number.isSafeInteger(allowance) || allowance < 0) {
      throw new RangeError('safetyAllowanceMs must be a non-negative safe integer');
    }
    this.quarantineMs = options.retentionMs + allowance;
    this.commandTimeoutMs = positiveSafeInteger(
      options.commandTimeoutMs ?? DEFAULT_CONTINUITY_TIMEOUT_MS,
      'commandTimeoutMs',
    );
    this.markerKey = `bpc:${options.namespace}:continuity`;
    this.now = options.now ?? Date.now;
    this.newEpoch = options.newEpoch ?? (() => `${this.now()}:${Math.random().toString(36).slice(2)}`);
  }

  /** True while authorization is quarantined. */
  isQuarantined(nowMs = this.now()): boolean {
    return nowMs < this.quarantinedUntilMs;
  }

  /** ms remaining in the current quarantine (0 if none). */
  quarantineRemainingMs(nowMs = this.now()): number {
    return Math.max(0, this.quarantinedUntilMs - nowMs);
  }

  private enterQuarantine(reason: AuthorizationQuarantineError['reason'], nowMs: number): void {
    const until = nowMs + this.quarantineMs;
    if (until > this.quarantinedUntilMs) this.quarantinedUntilMs = until;
  }

  /**
   * Reconcile against the persisted marker. Called before serving auth (e.g.
   * on boot and on a schedule). Establishes or adopts the epoch and quarantines
   * on any continuity break. Fails CLOSED: if the marker store is unreachable,
   * it quarantines rather than assuming continuity.
   */
  async reconcile(): Promise<void> {
    const nowMs = this.now();
    let current: string | null;
    try {
      current = await withTimeout(this.redis.get(this.markerKey), this.commandTimeoutMs);
    } catch {
      // Unknown continuity ⇒ fail closed.
      this.enterQuarantine('continuity_store_unavailable', nowMs);
      return;
    }

    if (current === null) {
      // Marker gone: state loss (flush/evict/restore-empty/new instance).
      // Claim a fresh epoch and quarantine until pre-loss nonces expire.
      const epoch = this.newEpoch();
      try {
        await withTimeout(this.redis.set(this.markerKey, epoch, 'NX'), this.commandTimeoutMs);
      } catch {
        this.enterQuarantine('continuity_store_unavailable', nowMs);
        return;
      }
      this.trustedEpoch = epoch;
      this.enterQuarantine('continuity_marker_lost', nowMs);
      return;
    }

    if (this.trustedEpoch === null) {
      // First reconcile of this process: adopt what is there, no quarantine —
      // the running key space is intact and this epoch is our baseline.
      this.trustedEpoch = current;
      return;
    }

    if (current !== this.trustedEpoch) {
      // Marker changed under us: failover/restore to a different instance.
      this.trustedEpoch = current;
      this.enterQuarantine('continuity_epoch_changed', nowMs);
    }
  }

  /**
   * Gate to call immediately before accepting an authorization / consuming a
   * nonce. Throws AuthorizationQuarantineError while quarantined.
   */
  assertAcceptable(nowMs = this.now()): void {
    if (nowMs < this.quarantinedUntilMs) {
      const reason = this.trustedEpoch === null
        ? 'continuity_store_unavailable'
        : 'continuity_marker_lost';
      throw new AuthorizationQuarantineError(reason, this.quarantinedUntilMs);
    }
  }
}
