import { createPrivateKey, sign } from 'node:crypto';

import type { SignCallback } from '@pagopa/io-wallet-oid-federation';

export const signJwtCallback: SignCallback = async ({ jwk, toBeSigned }) => {
  const alg = jwk.alg ?? 'ES256';
  const digestAlgorithm =
    alg === 'ES256' ? 'sha256' : alg === 'ES384' ? 'sha384' : alg === 'ES512' ? 'sha512' : undefined;

  if (!digestAlgorithm) {
    throw new Error(`Unsupported federation signing algorithm: ${alg}`);
  }

  const privateKey = createPrivateKey({ key: jwk, format: 'jwk' });
  const signature = sign(digestAlgorithm, Buffer.from(toBeSigned), {
    key: privateKey,
    dsaEncoding: 'ieee-p1363'
  });

  return new Uint8Array(signature);
};
