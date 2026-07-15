import { emitKeyGenerationCapture, generateKeypair, hashSecret, validateSecret } from '@bpc/core';
import type { AIRuntimeMetadata, BPCKeypair } from '@bpc/core';

export interface RegistrationResult {
  pairId: string;
  keypair: BPCKeypair;
}

export interface RegistrationRequest {
  name: string;
  scope: 'read' | 'read-write' | 'admin';
  mode: 'development' | 'production';
  secretHash: string;
  pubJwk: JsonWebKey;
}

export interface PrepareRegistrationOptions {
  runtimeMetadata?: Partial<AIRuntimeMetadata>;
  captureDetails?: Record<string, unknown>;
}

/** Generate keys and build a registration request. The owner must approve it server-side. */
export async function prepareRegistration(
  name: string,
  secret: string,
  scope: 'read' | 'read-write' | 'admin' = 'read-write',
  mode: 'development' | 'production' = 'development',
  options: PrepareRegistrationOptions = {},
): Promise<{ keypair: BPCKeypair; request: RegistrationRequest }> {
  const validation = validateSecret(secret);
  if (!validation.valid) {
    throw new TypeError(`BPC registration secret rejected: ${validation.reason}`);
  }
  const keypair = await generateKeypair({
    runtimeMetadata: options.runtimeMetadata,
    captureDetails: {
      operation: 'prepare_registration',
      name,
      scope,
      mode,
      ...options.captureDetails,
    },
  });
  const secretHash = await hashSecret(secret);
  emitKeyGenerationCapture({
    protocol: 'bpc',
    packageName: '@bpc/client-sdk',
    event: 'bpc.registration.prepared',
    keyFingerprint: keypair.fingerprint,
    algorithm: 'ECDSA P-256',
    extractable: false,
    runtime: options.runtimeMetadata,
    details: {
      name,
      scope,
      mode,
      ...options.captureDetails,
    },
  });
  return {
    keypair,
    request: { name, scope, mode, secretHash, pubJwk: keypair.pubJwk },
  };
}
