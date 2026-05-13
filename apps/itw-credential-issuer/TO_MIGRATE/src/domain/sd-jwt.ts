import type { Signer, Verifier } from '@sd-jwt/types';

import { ES256 } from '@sd-jwt/crypto-nodejs';
import { createHash } from 'node:crypto';

import { JwkPrivateKey, JwkPublicKey } from './z-jwk';

/**
 * Creates signer and verifier for ES256 algorithm.
 */
export async function createSignerVerifier({
  privateKey,
  publicKey
}: {
  privateKey: JwkPrivateKey;
  publicKey: JwkPublicKey;
}): Promise<[Signer, Verifier]> {
  return await Promise.all([ES256.getSigner(privateKey), ES256.getVerifier(publicKey)]);
}

/**
 * Creates a Subresource Integrity (SRI) hash for the given content using SHA-256.
 */
export function createSRIHash(content: string): string {
  const digest = createHash('sha256').update(content).digest('base64');
  return `sha256-${digest}`;
}
