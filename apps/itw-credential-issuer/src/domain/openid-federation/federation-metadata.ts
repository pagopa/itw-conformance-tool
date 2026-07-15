import { convertPemToBase64Der } from '@itw-conformance-tool/crypto';
import { createItWalletEntityConfiguration } from '@pagopa/io-wallet-oid-federation';
import { IoWalletSdkConfig } from '@pagopa/io-wallet-utils';

import { signCallback } from '../signer.js';
import { getEntityConfigurationClaimsMetadata } from './entity-configuration-metadata.js';

import type { JwksRepository } from '../signer.js';
import type { SignCallback } from '@pagopa/io-wallet-oid-federation';

export interface GetFederationMetadataOptions {
  baseURL: string;
  config: IoWalletSdkConfig;
  jwksRepository: JwksRepository;
  trustAnchorEntityId: string;
}

export const getFederationMetadata = async (options: GetFederationMetadataOptions): Promise<string> => {
  const jwk = options.jwksRepository.getSign();

  const signJwtCallback: SignCallback = async ({ toBeSigned }) => signCallback({ jwk: jwk.private, toBeSigned });

  return await createItWalletEntityConfiguration({
    claims: {
      authority_hints: [options.trustAnchorEntityId],
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
      iss: options.baseURL,
      jwks: {
        keys: [
          {
            ...options.jwksRepository.getSign().public,
            x5c: options.jwksRepository.issuerCertificateChain().map(convertPemToBase64Der)
          }
        ]
      },
      metadata: getEntityConfigurationClaimsMetadata(options.baseURL, options.jwksRepository, options.config),
      sub: options.baseURL
    },
    header: { alg: 'ES256', kid: jwk.public.kid, typ: 'entity-statement+jwt' },
    signJwtCallback
  });
};
