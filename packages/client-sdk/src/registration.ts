import { generateKeypair, hashSecret } from '@bpc/core';
import type { BPCKeypair } from '@bpc/core';

export interface RegistrationResult {
  pairId: string;
  keypair: BPCKeypair;
}

export interface RegistrationRequest {
  name: string;
  scope: 'read' | 'read-write' | 'full';
  mode: 'development' | 'production';
  secretHash: string;
  pubJwk: JsonWebKey;
}

/** Generate keys and build a registration request. The owner must approve it server-side. */
export async function prepareRegistration(
  name: string,
  secret: string,
  scope: 'read' | 'read-write' | 'full' = 'read-write',
  mode: 'development' | 'production' = 'development'
): Promise<{ keypair: BPCKeypair; request: RegistrationRequest }> {
  const keypair = await generateKeypair();
  const secretHash = await hashSecret(secret);
  return {
    keypair,
    request: { name, scope, mode, secretHash, pubJwk: keypair.pubJwk },
  };
}
