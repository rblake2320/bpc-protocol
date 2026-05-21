// Types
export type {
  BPCVerifyResult,
  StoredPair,
  PairRegistration,
  AnomalyCounters,
} from './types.js';
export type { BPCRequestData, BPCServerConfig } from './middleware.js';
export type { PairStore, NonceStoreBackend, AnomalyStore } from './store.js';
export type { AuditLog, AuditEntry, AuditAction, AuditSeverity } from './audit.js';
export type { RateLimiter, RateLimitResult } from './rate-limiter.js';
export type { RotationRequest, RotationResult } from './rotation.js';
export type { PgPool } from './pg-store.js';
export type { RedisClient } from './redis-nonce.js';
export type { RedisIncrClient } from './redis-anomaly.js';
export type { RedisZSetClient } from './rate-limiter.js';

// Admin endpoint authentication (Chain-3 / BPC-04 fix)
export type { AdminAuthConfig, AdminRequestHeaders } from './admin.js';
export { verifyAdminRequest } from './admin.js';

// Implementations
export { PairRegistry } from './registry.js';
export type { RedactedPair } from './registry.js';
export { AnomalyEngine } from './anomaly.js';
export { ServerNonceStore } from './nonce-store.js';
export { verifyBPCRequest } from './middleware.js';
export { MemoryPairStore, MemoryNonceBackend, MemoryAnomalyStore } from './memory-store.js';
export { PgPairStore, PG_SCHEMA } from './pg-store.js';
export { RedisNonceStore } from './redis-nonce.js';
export { RedisAnomalyStore } from './redis-anomaly.js';
export { MemoryRateLimiter, RedisRateLimiter } from './rate-limiter.js';
export { MemoryAuditLog, PgAuditLog, PG_AUDIT_SCHEMA } from './audit.js';
export { handleRotation } from './rotation.js';
export { BPC_ERRORS } from './errors.js';

// Factory function — creates a fully-wired BPC server with in-memory backends
import { PairRegistry } from './registry.js';
import { AnomalyEngine } from './anomaly.js';
import { ServerNonceStore } from './nonce-store.js';
import { MemoryPairStore, MemoryNonceBackend, MemoryAnomalyStore } from './memory-store.js';
import { MemoryAuditLog } from './audit.js';

export interface BPCServerInstance {
  registry: PairRegistry;
  nonceStore: ServerNonceStore;
  anomaly: AnomalyEngine;
  auditLog: MemoryAuditLog;
  store: MemoryPairStore;
}

export function createBPCServer(config?: { maxPairs?: number; lockoutCount?: number; sigWindowMs?: number }): BPCServerInstance {
  const store = new MemoryPairStore();
  const nonceBackend = new MemoryNonceBackend();
  const anomalyStore = new MemoryAnomalyStore();
  const auditLog = new MemoryAuditLog();

  return {
    registry: new PairRegistry(store, config?.maxPairs ?? 2000, config?.lockoutCount ?? 10),
    nonceStore: new ServerNonceStore(nonceBackend, config?.sigWindowMs ? config.sigWindowMs * 2 + 10_000 : 130_000),
    anomaly: new AnomalyEngine(anomalyStore),
    auditLog,
    store,
  };
}
