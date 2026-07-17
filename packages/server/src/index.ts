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
export type {
  RedisBackedNonceOptions,
  RedisBackedNonceStore,
  RedisClient,
} from './redis-nonce.js';
export type { RedisIncrClient } from './redis-anomaly.js';
export type { RedisZSetClient } from './rate-limiter.js';
export type {
  AgentCredentialCacheExpectedState,
  AgentCredentialCacheStore,
  CreateAgentCredentialCacheEntryInput,
  DpapiProtector,
  DpapiScope,
  SealedAgentCredentialCache,
  AgentCredentialCacheEntry,
} from './agent-cache.js';
export type {
  AuthorizationContext,
  AuthorizationContextResolver,
  AuthorizationResolutionInput,
  BindSessionInput,
  PrincipalChainVerifyResult,
  PrincipalCheckpoint,
  PrincipalEventType,
  PrincipalRecord,
  PrincipalSessionLedger,
  PrincipalSessionProof,
  PrincipalSessionProofPayload,
  PrincipalStreamEvent,
  PrincipalStreamRecord,
  FallbackAuthorizationInput,
  FallbackAuthorizationResult,
  SealPrincipalCacheInput,
  SealedPrincipalCache,
  SessionBinding,
} from './principal-session.js';

// Admin endpoint authentication (Chain-3 / BPC-04 fix)
export type { AdminAuthConfig, AdminRequestHeaders } from './admin.js';
export { verifyAdminRequest } from './admin.js';

// Implementations
export {
  CacheExpiredError,
  CacheTamperedError,
  CacheUnavailableError,
  DpapiFailClosedAgentCache,
  MemoryAgentCredentialCacheStore,
  WindowsCurrentUserDpapiProtector,
  computePermissionsHash,
  createAgentCredentialCacheEntry,
  openAgentCredentialCacheEntry,
  sealAgentCredentialCacheEntry,
} from './agent-cache.js';
export { PairRegistry } from './registry.js';
export type { RedactedPair } from './registry.js';
export { AnomalyEngine } from './anomaly.js';
export { NonceStoreUnavailableError, ServerNonceStore } from './nonce-store.js';
export {
  AuthorizationQuarantineError,
  DEFAULT_CONTINUITY_SAFETY_ALLOWANCE_MS,
  DEFAULT_CONTINUITY_TIMEOUT_MS,
  EvictionPolicyError,
  RedisContinuityGuard,
  assertNoEvictionPolicy,
  startContinuityReconcileLoop,
} from './redis-continuity.js';
export type {
  ContinuityGate,
  ReconcileLoopHandle,
  ReconcileLoopOptions,
  RedisConfigClient,
  RedisContinuityClient,
  RedisContinuityOptions,
} from './redis-continuity.js';
export {
  CANON_MAX_DEPTH,
  CANON_MAX_NODES,
  CANON_MAX_STRING_BYTES,
  CANON_MAX_TOTAL_BYTES,
  ContractValidationError,
  FENCE_TOKEN_PATTERN,
  HA_OUTBOX_CONTRACT_VERSION,
  HA_OUTBOX_DIGEST_DOMAIN,
  ID_PATTERN,
  OutboxBackpressureError,
  STREAM_HEAD_ALGS,
  StaleFenceError,
  assertHeaderConformant,
  assertEpochTransitionConformant,
  assertStreamHeadBinds,
  canonicalOpDigest,
  canonicalize,
  epochTransitionDigest,
  fenceTokenToDecimal,
  idempotencyKeyOf,
  streamHeadDigest,
} from './ha-outbox-contract.js';
export type {
  ContractVersion,
  DurableOutbox,
  DurableTx,
  EpochTransitionAuthorizer,
  EpochTransitionRecord,
  FenceToken,
  HotpMutationSanitizer,
  IdempotencyKey,
  MutationSanitizer,
  OutboxPublisher,
  OutboxRecord,
  OutboxRecordHeader,
  PromotionFence,
  PublisherBackpressure,
  ReceiverCheckpoint,
  ReceiverDecision,
  SanitizedMutation,
  SignedStreamHead,
  StreamHeadAlg,
  StreamHeadVerifier,
  TskHotpMutation,
  TskReceiverCheckpoint,
} from './ha-outbox-contract.js';
export {
  CheckpointConflictError,
  CheckpointInconsistentError,
  CheckpointUnavailableError,
  ContinuityValidationError,
  MalformedCasError,
  NotAuthorizedError,
  RedisAheadError,
  RollbackCheckpointGuard,
  RollbackDetectedError,
  SequenceExhaustedError,
  WitnessMissingError,
} from './rollback-checkpoint.js';
export type {
  CheckpointState,
  MonotonicCheckpoint,
  RedisSequenceView,
  RollbackCheckpointOptions,
  ProvisioningAuthorizer,
  RollbackVerdict,
} from './rollback-checkpoint.js';
export {
  HA_OUTBOX_PG_SCHEMA,
  PgDurableOutbox,
  PgDurablePublisher,
  PgPromotionFence,
  PgReceiverCheckpoint,
  createBoundTx,
} from './ha-outbox-pg.js';
export type {
  MutationApplier,
  OutboxTransport,
  PgBackend,
  PgExecutor,
  PgOutboxOptions,
  PgTransactor,
  PgTx,
} from './ha-outbox-pg.js';
export {
  RedisContinuityConfigurationError,
  createGovernedRedisBackedNonceStore,
} from './redis-governed.js';
export type {
  GovernedRedisBackedNonceOptions,
  GovernedRedisBackedNonceStore,
  RedisAtomicClient,
} from './redis-governed.js';
export { verifyBPCRequest } from './middleware.js';
export { MemoryPairStore, MemoryNonceBackend, MemoryAnomalyStore } from './memory-store.js';
export { ReplicatingPairStore } from './replicating-store.js';
export type { ReplicaTarget, ReplicaOp, ReplicatingStoreOptions } from './replicating-store.js';
export {
  authorizeReplica, validateReplicaOp, applyReplicaOp, handleReplicaIngest,
} from './replica-receiver.js';
export type { ReplicaApplyResult } from './replica-receiver.js';
export {
  DEFAULT_REPLICA_FRESHNESS_MS,
  MemoryReplicaApplyGuard,
  MemoryReplicaSequenceSource,
  REPLICA_ENVELOPE_VERSION,
  canonicalReplicaEnvelope,
  replicaOperationDigest,
  signReplicaEnvelope,
  validateReplicaEnvelope,
  verifyReplicaEnvelopeSignature,
} from './replica-envelope.js';
export type {
  ReplicaApplyDisposition,
  ReplicaApplyGuard,
  ReplicaEnvelope,
  ReplicaSequenceSource,
} from './replica-envelope.js';
export { PromotionController, assertWritable, handlePromotionCommand } from './promotion.js';
export type { NodeRole, PromotionSnapshot, PromotionCommand } from './promotion.js';
export { PgPairStore, PG_SCHEMA } from './pg-store.js';
export {
  DEFAULT_NONCE_SAFETY_BUFFER_MS,
  DEFAULT_REDIS_NONCE_TIMEOUT_MS,
  RedisNonceStore,
  createRedisBackedNonceStore,
  deriveNonceRetentionMs,
} from './redis-nonce.js';
export { RedisAnomalyStore } from './redis-anomaly.js';
export { MemoryRateLimiter, RedisRateLimiter } from './rate-limiter.js';
// GENESIS_HASH exported so consumers can anchor chain verification externally
// (store the genesis hash at startup and compare later to detect forgery or truncation).
export { MemoryAuditLog, PgAuditLog, PG_AUDIT_SCHEMA, GENESIS_HASH } from './audit.js';
export { handleRotation } from './rotation.js';
export { BPC_ERRORS } from './errors.js';
export {
  MemoryPrincipalSessionLedger,
  PRINCIPAL_BINDING_PURPOSE,
  PRINCIPAL_GENESIS_HASH,
  buildPrincipalSessionProofPayload,
  makeStreamId,
  principalIdFromFingerprint,
  sealPrincipalCache,
  verifyPrincipalSessionProof,
  verifyFallbackAuthorization,
} from './principal-session.js';

// Factory function — creates a fully-wired BPC server with in-memory backends
import { PairRegistry } from './registry.js';
import { AnomalyEngine } from './anomaly.js';
import { ServerNonceStore } from './nonce-store.js';
import { MemoryPairStore, MemoryNonceBackend, MemoryAnomalyStore } from './memory-store.js';
import { MemoryAuditLog } from './audit.js';
import { MemoryPrincipalSessionLedger } from './principal-session.js';

export interface BPCServerInstance {
  registry: PairRegistry;
  nonceStore: ServerNonceStore;
  anomaly: AnomalyEngine;
  auditLog: MemoryAuditLog;
  principalLedger: MemoryPrincipalSessionLedger;
  store: MemoryPairStore;
}

export interface BPCServerFactoryConfig {
  maxPairs?: number;
  lockoutCount?: number;
  sigWindowMs?: number;
  /** Inject a distributed or deployment-specific nonce store. */
  nonceStore?: ServerNonceStore;
}

export function createBPCServer(config?: BPCServerFactoryConfig): BPCServerInstance {
  const store = new MemoryPairStore();
  const nonceBackend = new MemoryNonceBackend();
  const anomalyStore = new MemoryAnomalyStore();
  const auditLog = new MemoryAuditLog();
  const principalLedger = new MemoryPrincipalSessionLedger();

  return {
    registry: new PairRegistry(store, config?.maxPairs ?? 2000, config?.lockoutCount ?? 10),
    nonceStore: config?.nonceStore ?? new ServerNonceStore(
      nonceBackend,
      config?.sigWindowMs ? config.sigWindowMs * 2 + 10_000 : 130_000,
    ),
    anomaly: new AnomalyEngine(anomalyStore),
    auditLog,
    principalLedger,
    store,
  };
}
