import type { JwksRepository } from '@/domain/signer';
import type { SignCallback } from '@pagopa/io-wallet-oid-federation';

import { signJwtCallback } from '@/domain/signer';
import { createItWalletEntityConfiguration } from '@pagopa/io-wallet-oid-federation';
import { IoWalletSdkConfig } from '@pagopa/io-wallet-utils';

import { getEntityConfigurationClaimsMetadata } from './entity-configuration-metadata';

export interface GetFederationMetadataOptions {
  /* * The base URL of the OpenID Federation server. */
  baseURL: string;

  /* * The SDK config used to derive the active IT Wallet spec version. */
  config: IoWalletSdkConfig;

  /* * The JWKs repository used to sign the JWT. */
  jwksRepository: JwksRepository;
}

export const getFederationMetadata = async (options: GetFederationMetadataOptions): Promise<string> => {
  const jwk = options.jwksRepository.getSign();

  const signCallback: SignCallback = async ({ toBeSigned }) => signJwtCallback({ jwk: jwk.private, toBeSigned });

  return await createItWalletEntityConfiguration({
    claims: {
      authority_hints: [`${options.baseURL}/trust_anchor`],
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
      iss: options.baseURL,
      jwks: {
        keys: [
          {
            ...options.jwksRepository.getSign().public,
            x5c: [options.jwksRepository.iacaX509()]
          }
        ]
      },
      metadata: getEntityConfigurationClaimsMetadata(options.baseURL, options.jwksRepository, options.config),
      sub: options.baseURL
    },
    header: { alg: 'ES256', kid: jwk.public.kid, typ: 'entity-statement+jwt' },
    signJwtCallback: signCallback
  });
};
