import type { AnomalyCounters } from './types.js';

export class AnomalyEngine {
  private global: AnomalyCounters = {
    unknownPairProbes: 0,
    sigFailures: 0,
    replayAttempts: 0,
    expiredTimestamps: 0,
    totalRequests: 0,
    deniedRequests: 0,
  };

  recordRequest(): void { this.global.totalRequests++; }
  recordDenied(): void { this.global.deniedRequests++; }
  recordUnknownPair(): void { this.global.unknownPairProbes++; }
  recordSigFailure(): void { this.global.sigFailures++; }
  recordReplay(): void { this.global.replayAttempts++; }
  recordExpiredTimestamp(): void { this.global.expiredTimestamps++; }

  threatScore(): number {
    const g = this.global;
    if (g.totalRequests === 0) return 0;
    const unknownRate = Math.min(g.unknownPairProbes / Math.max(g.totalRequests, 1), 1);
    const sigRate = Math.min(g.sigFailures / Math.max(g.totalRequests, 1), 1);
    const replayRate = Math.min(g.replayAttempts / Math.max(g.totalRequests, 1), 1);
    const expiredRate = Math.min(g.expiredTimestamps / Math.max(g.totalRequests, 1), 1);
    return Math.round((unknownRate * 30 + sigRate * 30 + replayRate * 20 + expiredRate * 20) * 100);
  }

  counters(): AnomalyCounters { return { ...this.global }; }
}
