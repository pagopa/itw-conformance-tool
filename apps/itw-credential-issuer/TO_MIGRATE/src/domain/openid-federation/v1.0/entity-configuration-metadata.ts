import type { JwksRepository } from '@/domain/signer';
import type { ItWalletEntityConfigurationClaimsOptions, ItWalletMetadataV1_0 } from '@pagopa/io-wallet-oid-federation';

import { itWalletMetadataV1_0 } from '@pagopa/io-wallet-oid-federation';
import { ValidationError } from '@pagopa/io-wallet-utils';

import { pidIdentification, verifierPublicKeys } from '../shared/constants';
import { createCredentialIssuerMetadataV1_0 } from './credential-issuer-metadata';

export const getEntityConfigurationClaimsMetadataV1_0 = (
  baseURL: string,
  jwksRepository: JwksRepository
): ItWalletEntityConfigurationClaimsOptions['metadata'] => {
  const metadata = {
    federation_entity: {
      contacts: ['info@pagopa.it'],
      // tos_uri: "https://io.italia.it/privacy-policy", not yet supported
      federation_resolve_endpoint: `${baseURL}/resolve`,
      homepage_uri: 'https://io.italia.it',
      logo_uri: 'https://io.italia.it/assets/img/io-it-logo-blue.svg',
      organization_name: 'PagoPa S.p.A.',
      policy_uri: 'https://io.italia.it/privacy-policy'
    },
    oauth_authorization_server: {
      acr_values_supported: [
        'https://trust-registry.eid-wallet.example.it/loa/low',
        'https://trust-registry.eid-wallet.example.it/loa/substantial',
        'https://trust-registry.eid-wallet.example.it/loa/high'
      ],
      authorization_endpoint: `${baseURL}/authorize`,
      authorization_signing_alg_values_supported: ['ES256', 'ES384', 'ES512'],
      client_registration_types_supported: ['automatic'],
      code_challenge_methods_supported: ['S256'],
      grant_types_supported: ['authorization_code'],
      issuer: baseURL,
      // client_id_schemes_supported: ["pre-registered", "x509_san_dns"],
      jwks: {
        keys: [jwksRepository.getSign().public]
      },
      pushed_authorization_request_endpoint: `${baseURL}/as/par`,
      request_object_signing_alg_values_supported: ['ES256', 'ES384', 'ES512'],
      response_modes_supported: ['query', 'form_post.jwt'],
      response_types_supported: ['code'],
      scopes_supported: [pidIdentification],
      token_endpoint: `${baseURL}/token`,
      token_endpoint_auth_methods_supported: ['attest_jwt_client_auth'],
      // vp_formats_supported: {
      //   "sd+sd-jwt": {
      //     "sd-jwt_alg_values": ["ES256"],
      //   },
      // },
      token_endpoint_auth_signing_alg_values_supported: ['ES256', 'ES384', 'ES512']
    },
    openid_credential_issuer: {
      client_registration_types_supported: ['automatic'],
      ...createCredentialIssuerMetadataV1_0(baseURL, jwksRepository)
    },
    openid_credential_verifier: {
      application_type: 'web',
      authorization_encrypted_response_alg: 'ECDH-ES',
      authorization_encrypted_response_enc: 'A128CBC-HS256',
      authorization_signed_response_alg: 'ES256',
      client_id: baseURL,
      client_name: 'PagoPa S.p.A.',
      client_registration_types: ['automatic'],
      contacts: ['info@pagopa.it'],
      default_acr_values: [
        'https://trust-registry.eid-wallet.example.it/loa/substantial',
        'https://trust-registry.eid-wallet.example.it/loa/high'
      ],
      jwks: {
        keys: verifierPublicKeys
      },
      request_object_signing_alg_values_supported: ['ES256', 'ES384', 'ES512'],
      request_uris: [`${baseURL}/authorize`],
      response_uris: [`${baseURL}/presentation-response`],
      vp_formats: {
        'dc+sd-jwt': {
          'sd-jwt_alg_values': ['ES256', 'ES384', 'ES512']
        }
      }
    }
  } satisfies ItWalletMetadataV1_0;

  const parsedMetadata = itWalletMetadataV1_0.safeParse(metadata);
  if (!parsedMetadata.success) {
    throw new ValidationError('Invalid entity configuration metadata', parsedMetadata.error);
  }

  return parsedMetadata.data;
};
