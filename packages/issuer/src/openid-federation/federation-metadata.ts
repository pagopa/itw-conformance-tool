import { createItWalletEntityConfiguration } from '@pagopa/io-wallet-oid-federation';
import { IoWalletSdkConfig } from '@pagopa/io-wallet-utils';

import { signJwtCallback } from '../signer.js';
import { getEntityConfigurationClaimsMetadata } from './entity-configuration-metadata.js';

import type { JwksRepository } from '../signer.js';
import type { SignCallback } from '@pagopa/io-wallet-oid-federation';

export interface GetFederationMetadataOptions {
  baseURL: string;
  config: IoWalletSdkConfig;
  jwksRepository: JwksRepository;
}

export const getFederationMetadata = async (options: GetFederationMetadataOptions): Promise<string> => {
  const jwk = options.jwksRepository.getSign();

  const signCallback: SignCallback = async ({ toBeSigned }) =>
    signJwtCallback({ jwk: jwk.private as Parameters<SignCallback>[0]['jwk'], toBeSigned });

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
            x5c: [options.jwksRepository.iacaX509()],
          },
        ],
      },
      metadata: getEntityConfigurationClaimsMetadata(
        options.baseURL,
        options.jwksRepository,
        options.config,
      ),
      sub: options.baseURL,
    },
    header: { alg: 'ES256', kid: jwk.public.kid, typ: 'entity-statement+jwt' },
    signJwtCallback: signCallback,
  });
};
