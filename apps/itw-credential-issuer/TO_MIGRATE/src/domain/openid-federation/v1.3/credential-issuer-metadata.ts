import type { JwksRepository } from '@/domain/signer';
import type { ItWalletCredentialIssuerMetadataV1_3 } from '@pagopa/io-wallet-oid-federation';

import { itWalletCredentialIssuerMetadataV1_3 } from '@pagopa/io-wallet-oid-federation';
import { ItWalletSpecsVersion, ValidationError } from '@pagopa/io-wallet-utils';

import {
  dc_sd_jwt_EuropeanDisabilityCard,
  dc_sd_jwt_PersonIdentificationData,
  mso_mdoc_PersonIdentificationData,
  mso_mdoc_mDL
} from '../shared/credential-configurations';

export const createCredentialIssuerMetadataV1_3 = (
  baseURL: string,
  jwksRepository: JwksRepository
): ItWalletCredentialIssuerMetadataV1_3 => {
  const credentialConfigurationsSupported = {
    dc_sd_jwt_EuropeanDisabilityCard: dc_sd_jwt_EuropeanDisabilityCard(baseURL),
    dc_sd_jwt_PersonIdentificationData: dc_sd_jwt_PersonIdentificationData(baseURL, ItWalletSpecsVersion.V1_3),
    mso_mdoc_PersonIdentificationData: mso_mdoc_PersonIdentificationData(baseURL, ItWalletSpecsVersion.V1_3),
    'org.iso.18013.5.1.mDL': mso_mdoc_mDL(baseURL)
  };

  const metadata = {
    batch_credential_issuance: {
      batch_size: 30
    },
    credential_configurations_supported: Object.fromEntries(
      Object.entries(credentialConfigurationsSupported).map(([credentialId, credentialConfiguration]) => [
        credentialId,
        {
          ...credentialConfiguration,
          authentic_sources: {
            dataset_id: credentialId,
            entity_id: baseURL
          },
          credential_metadata: {
            claims: credentialConfiguration.claims,
            display: credentialConfiguration.display.map((display) => ({
              background_color: display.background_color,
              locale: display.locale,
              logo: display.logo
                ? {
                    alt_text: display.logo.alt_text,
                    uri: display.logo.url
                  }
                : undefined,
              name: display.name
            }))
          },
          schema_id: credentialId
        }
      ])
    ),
    credential_endpoint: `${baseURL}/credential`,
    credential_issuer: baseURL,
    deferred_credential_endpoint: `${baseURL}/deferred`,
    display: [
      {
        background_color: '#12107c',
        locale: 'it-IT',
        logo: {
          alt_text: 'logo',
          uri: 'https://io.italia.it/assets/img/io-it-logo-blue.svg'
        },
        name: 'PagoPA S.p.A.'
      }
    ],
    jwks: {
      keys: [jwksRepository.getSign().public]
    },
    nonce_endpoint: `${baseURL}/nonce`,
    notification_endpoint: `${baseURL}/notification`,
    status_list_aggregation_endpoint: `${baseURL}/status`,
    trust_frameworks_supported: ['it_cie', 'eudi_wallet', 'it_wallet']
  };

  const parsedMetadata = itWalletCredentialIssuerMetadataV1_3.safeParse(metadata);
  if (!parsedMetadata.success) {
    throw new ValidationError('Invalid credential issuer metadata', parsedMetadata.error);
  }

  return parsedMetadata.data;
};
