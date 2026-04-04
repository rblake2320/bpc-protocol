import type { AnomalyStore } from './store.js';
import type { AnomalyCounters } from './types.js';

const WINDOW_MS = 3_600_000; // 1 hour

export class AnomalyEngine {
  constructor(private store: AnomalyStore) {}

  async recordRequest(pairId?: string): Promise<void> {
    await this.store.increment('global:total', WINDOW_MS);
    if (pairId) await this.store.increment(`pair:${pairId}:total`, WINDOW_MS);
  }

  async recordDenied(pairId?: string): Promise<void> {
    await this.store.increment('global:denied', WINDOW_MS);
    if (pairId) await this.store.increment(`pair:${pairId}:denied`, WINDOW_MS);
  }

  async recordUnknownPair(): Promise<void> {
    await this.store.increment('global:unknown_pair', WINDOW_MS);
  }

  async recordSigFailure(pairId?: string): Promise<void> {
    await this.store.increment('global:sig_fail', WINDOW_MS);
    if (pairId) await this.store.increment(`pair:${pairId}:sig_fail`, WINDOW_MS);
  }

  async recordReplay(pairId?: string): Promise<void> {
    await this.store.increment('global:replay', WINDOW_MS);
    if (pairId) await this.store.increment(`pair:${pairId}:replay`, WINDOW_MS);
  }

  async recordExpiredTimestamp(pairId?: string): Promise<void> {
    await this.store.increment('global:expired_ts', WINDOW_MS);
    if (pairId) await this.store.increment(`pair:${pairId}:expired_ts`, WINDOW_MS);
  }

  async threatScore(): Promise<number> {
    const total = await this.store.get('global:total');
    if (total === 0) return 0;
    const unknownPair = await this.store.get('global:unknown_pair');
    const sigFail = await this.store.get('global:sig_fail');
    const replay = await this.store.get('global:replay');
    const expiredTs = await this.store.get('global:expired_ts');

    const unknownRate = Math.min(unknownPair / total, 1);
    const sigRate = Math.min(sigFail / total, 1);
    const replayRate = Math.min(replay / total, 1);
    const expiredRate = Math.min(expiredTs / total, 1);
    return Math.round((unknownRate * 30 + sigRate * 30 + replayRate * 20 + expiredRate * 20) * 100);
  }

  async counters(): Promise<AnomalyCounters> {
    return {
      unknownPairProbes: await this.store.get('global:unknown_pair'),
      sigFailures: await this.store.get('global:sig_fail'),
      replayAttempts: await this.store.get('global:replay'),
      expiredTimestamps: await this.store.get('global:expired_ts'),
      totalRequests: await this.store.get('global:total'),
      deniedRequests: await this.store.get('global:denied'),
    };
  }

  async pairCounters(pairId: string): Promise<{ total: number; denied: number; sigFail: number; replay: number }> {
    return {
      total: await this.store.get(`pair:${pairId}:total`),
      denied: await this.store.get(`pair:${pairId}:denied`),
      sigFail: await this.store.get(`pair:${pairId}:sig_fail`),
      replay: await this.store.get(`pair:${pairId}:replay`),
    };
  }
}
