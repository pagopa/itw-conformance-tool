import { IoWalletSdkConfig, ItWalletSpecsVersion } from '@pagopa/io-wallet-utils';

import { createCredentialIssuerMetadataV1_0 } from './v1.0/credential-issuer-metadata.js';
import { createCredentialIssuerMetadataV1_3 } from './v1.3/credential-issuer-metadata.js';

import type { JwksRepository } from '../signer.js';
import type {
  ItWalletCredentialIssuerMetadata,
  ItWalletCredentialIssuerMetadataV1_3,
} from '@pagopa/io-wallet-oid-federation';

export const createCredentialIssuerMetadata = (
  baseURL: string,
  jwksRepository: JwksRepository,
  config: IoWalletSdkConfig,
): ItWalletCredentialIssuerMetadata | ItWalletCredentialIssuerMetadataV1_3 => {
  if (config.isVersion(ItWalletSpecsVersion.V1_3)) {
    return createCredentialIssuerMetadataV1_3(baseURL, jwksRepository);
  }
  return createCredentialIssuerMetadataV1_0(baseURL, jwksRepository);
};
