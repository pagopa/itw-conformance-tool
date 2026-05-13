import { createHash } from 'node:crypto';

import { ES256 } from '@sd-jwt/crypto-nodejs';

import type { JwkPrivateKey, JwkPublicKey } from './z-jwk.js';
import type { Signer, Verifier } from '@sd-jwt/types';

export async function createSignerVerifier({
  privateKey,
  publicKey,
}: {
  privateKey: JwkPrivateKey;
  publicKey: JwkPublicKey;
}): Promise<[Signer, Verifier]> {
  return await Promise.all([ES256.getSigner(privateKey), ES256.getVerifier(publicKey)]);
}

export function createSRIHash(content: string): string {
  const hash = createHash('sha256').update(content).digest('base64');
  return `sha256-${hash}`;
}
