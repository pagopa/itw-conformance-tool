import { CompactSign, type JWK, importJWK } from 'jose';

import { type ECKey, type ECPrivateKey, type JwkPrivateKey, type JwkPublicKey } from './z-jwk.js';

import type { SignCallback } from '@pagopa/io-wallet-oid-federation';

export interface JwksRepository {
  readonly getEncrypt: () => JwkKeyPair<'EC'>;
  readonly getSign: () => JwkKeyPair<'EC'>;
  readonly iacaX509: () => string;
}

interface JwkKeyPair<A> {
  readonly private: { readonly kty: A } & JwkPrivateKey & Required<Pick<ECPrivateKey, 'kid'>>;
  readonly public: { readonly kty: A } & JwkPublicKey & Required<Pick<ECKey, 'kid'>>;
}

const base64urlToBase64 = (base64url: string): string =>
  base64url.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (base64url.length % 4)) % 4);

export const signJwtCallback: SignCallback = async ({ jwk, toBeSigned }) => {
  const alg = (jwk as { alg?: string }).alg ?? 'ES256';
  const key = await importJWK(jwk as unknown as JWK, alg);

  const jws = await new CompactSign(toBeSigned).setProtectedHeader({ alg }).sign(key);

  const parts = jws.split('.');
  if (parts.length !== 3) {
    throw new Error('JWS compact format is not valid');
  }

  const signatureBase64Url = parts[2] as string;
  const signatureBase64 = base64urlToBase64(signatureBase64Url);
  const signatureBytes = new Uint8Array(Buffer.from(signatureBase64, 'base64'));

  return signatureBytes;
};
