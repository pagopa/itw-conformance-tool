import { CompactSign, importJWK } from 'jose';

import type { SignCallback } from '@pagopa/io-wallet-oid-federation';

export const signJwtCallback: SignCallback = async ({ jwk, toBeSigned }) => {
  const alg = jwk.alg ?? 'ES256';
  const key = await importJWK(jwk, alg);
  const jws = await new CompactSign(toBeSigned).setProtectedHeader({ alg }).sign(key);

  const parts = jws.split('.');
  if (parts.length !== 3) {
    throw new Error('JWS compact format is not valid');
  }

  const signatureBase64Url = parts[2];
  const signatureBase64 = Buffer.from(signatureBase64Url, 'base64url').toString('base64');
  return new Uint8Array(Buffer.from(signatureBase64, 'base64'));
};
