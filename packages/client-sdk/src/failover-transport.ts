/**
 * FailoverTransport — Option A client-side endpoint selection.
 *
 * READS auto-fail-over from primary to a replica on health-check failure, stick
 * to the replica until the primary recovers, and fail BACK automatically once a
 * primary health probe passes again.
 *
 * WRITES are primary-only, ALWAYS. The transport never silently routes a write
 * to a replica — that is what prevents split-brain on the client side. If the
 * primary is unhealthy, write() throws PrimaryUnavailableError. Promotion of a
 * replica to a writer is a deliberate guard action on the server (see
 * PromotionController) and, if a promoted replica is to receive writes, the
 * operator repoints `primary` here — the client never makes that decision.
 *
 *  FT-01 Reads: consecutive-miss failover within a window, sticky, auto-failback.
 *  FT-02 Writes: primary-only; PrimaryUnavailableError when the primary is down.
 *  FT-03 Health: a 2xx on healthPath clears misses and restores the endpoint.
 */

export interface FailoverConfig {
  /** Authoritative writer + preferred reader. */
  primary: string;
  /** Ordered read fallbacks. */
  replicas?: string[];
  /** GET path probed for health. 2xx = healthy. Default '/health'. */
  healthPath?: string;
  /** Consecutive misses before an endpoint is marked unhealthy. Default 3. */
  missThreshold?: number;
  /** Misses must occur within this window (ms) to accumulate. Default 15_000. */
  windowMs?: number;
  /** Per-request timeout (ms). Default 3_000. */
  timeoutMs?: number;
  /** Injectable fetch for tests. Defaults to global fetch. */
  fetchImpl?: typeof fetch;
}

export class PrimaryUnavailableError extends Error {
  constructor(message = 'primary is unavailable; writes are primary-only (Option A)') {
    super(message);
    this.name = 'PrimaryUnavailableError';
  }
}

interface EndpointState {
  url: string;
  healthy: boolean;
  streak: number;          // consecutive misses
  streakStartedAt: number | null;
}

const DEFAULTS = { healthPath: '/health', missThreshold: 3, windowMs: 15_000, timeoutMs: 3_000 };

export class FailoverTransport {
  private readonly primary: EndpointState;
  private readonly replicas: EndpointState[];
  private readonly healthPath: string;
  private readonly missThreshold: number;
  private readonly windowMs: number;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(cfg: FailoverConfig) {
    this.primary = { url: cfg.primary, healthy: true, streak: 0, streakStartedAt: null };
    this.replicas = (cfg.replicas ?? []).map((url) => ({ url, healthy: true, streak: 0, streakStartedAt: null }));
    this.healthPath = cfg.healthPath ?? DEFAULTS.healthPath;
    this.missThreshold = cfg.missThreshold ?? DEFAULTS.missThreshold;
    this.windowMs = cfg.windowMs ?? DEFAULTS.windowMs;
    this.timeoutMs = cfg.timeoutMs ?? DEFAULTS.timeoutMs;
    this.fetchImpl = cfg.fetchImpl ?? fetch;
  }

  /** Current best read endpoint URL (primary if healthy, else first healthy replica). */
  get activeReadUrl(): string {
    if (this.primary.healthy) return this.primary.url;
    const r = this.replicas.find((e) => e.healthy);
    return (r ?? this.primary).url;
  }

  get primaryHealthy(): boolean { return this.primary.healthy; }

  // ── FT-01 Reads ─────────────────────────────────────────────────────────────
  async read(path: string, init: RequestInit = {}): Promise<Response> {
    const chain = [this.primary, ...this.replicas];
    let lastErr: unknown;
    for (const ep of chain) {
      if (!ep.healthy) continue;
      try {
        const res = await this.fetchOnce(ep.url + path, { ...init, method: (init.method ?? 'GET') });
        this.recordSuccess(ep);
        return res;
      } catch (e) {
        lastErr = e;
        this.recordMiss(ep);
        // fall through to next healthy endpoint
      }
    }
    // Nothing healthy responded — try any endpoint once as a last resort.
    for (const ep of chain) {
      try {
        const res = await this.fetchOnce(ep.url + path, { ...init, method: (init.method ?? 'GET') });
        this.recordSuccess(ep);
        return res;
      } catch (e) { lastErr = e; }
    }
    throw lastErr ?? new Error('all endpoints failed');
  }

  // ── FT-02 Writes (primary-only) ──────────────────────────────────────────────
  async write(path: string, init: RequestInit = {}): Promise<Response> {
    if (!this.primary.healthy) {
      throw new PrimaryUnavailableError();
    }
    try {
      const res = await this.fetchOnce(this.primary.url + path, { ...init, method: (init.method ?? 'POST') });
      this.recordSuccess(this.primary);
      return res;
    } catch (e) {
      this.recordMiss(this.primary);
      // Do NOT fail a write over to a replica — that would risk split-brain.
      throw e instanceof Error ? e : new Error('primary write failed');
    }
  }

  // ── FT-03 Health probe / fail-back ───────────────────────────────────────────
  /** Probe the primary's health endpoint; a 2xx restores it (auto fail-back). */
  async probePrimary(): Promise<boolean> {
    return this.probe(this.primary);
  }

  /** Probe every endpoint; returns the resulting health map. */
  async probeAll(): Promise<Record<string, boolean>> {
    const all = [this.primary, ...this.replicas];
    await Promise.all(all.map((ep) => this.probe(ep)));
    return Object.fromEntries(all.map((ep) => [ep.url, ep.healthy]));
  }

  private async probe(ep: EndpointState): Promise<boolean> {
    try {
      const res = await this.fetchOnce(ep.url + this.healthPath, { method: 'GET' });
      if (res.ok) { this.recordSuccess(ep); return true; }
      this.recordMiss(ep);
      return ep.healthy;
    } catch {
      this.recordMiss(ep);
      return ep.healthy;
    }
  }

  // ── internals ─────────────────────────────────────────────────────────────────
  private async fetchOnce(url: string, init: RequestInit): Promise<Response> {
    return this.fetchImpl(url, { ...init, signal: AbortSignal.timeout(this.timeoutMs) });
  }

  private recordSuccess(ep: EndpointState): void {
    ep.streak = 0;
    ep.streakStartedAt = null;
    ep.healthy = true;           // FT-03 auto fail-back
  }

  private recordMiss(ep: EndpointState): void {
    const now = Date.now();
    if (ep.streakStartedAt === null || now - ep.streakStartedAt > this.windowMs) {
      // Start a fresh streak (old misses aged out of the window).
      ep.streak = 1;
      ep.streakStartedAt = now;
    } else {
      ep.streak += 1;
    }
    if (ep.streak >= this.missThreshold) {
      ep.healthy = false;
    }
  }
}
