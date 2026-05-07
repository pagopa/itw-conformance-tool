import type { JwksRepository } from "@/domain/signer";
import type {
  ItWalletEntityConfigurationClaimsOptions,
  MetadataV1_3,
} from "@pagopa/io-wallet-oid-federation";

import { itWalletMetadataV1_3 } from "@pagopa/io-wallet-oid-federation";
import { ValidationError } from "@pagopa/io-wallet-utils";

import { pidIdentification, verifierPublicKeys } from "../shared/constants";
import { createCredentialIssuerMetadataV1_3 } from "./credential-issuer-metadata";

export const getEntityConfigurationClaimsMetadataV1_3 = (
  baseURL: string,
  jwksRepository: JwksRepository,
): ItWalletEntityConfigurationClaimsOptions["metadata"] => {
  const metadata = {
    federation_entity: {
      contacts: ["info@pagopa.it"],
      // tos_uri: "https://io.italia.it/privacy-policy", not yet supported
      federation_resolve_endpoint: `${baseURL}/resolve`,
      homepage_uri: "https://io.italia.it",
      logo_uri: "https://io.italia.it/assets/img/io-it-logo-blue.svg",
      organization_name: "PagoPa S.p.A.",
      policy_uri: "https://io.italia.it/privacy-policy",
    },
    oauth_authorization_server: {
      acr_values_supported: [
        "https://trust-registry.eid-wallet.example.it/loa/low",
        "https://trust-registry.eid-wallet.example.it/loa/substantial",
        "https://trust-registry.eid-wallet.example.it/loa/high",
      ],
      authorization_endpoint: `${baseURL}/authorize`,
      authorization_signing_alg_values_supported: ["ES256", "ES384", "ES512"],
      client_attestation_pop_signing_alg_values_supported: [
        "ES256",
        "ES384",
        "ES512",
      ],
      client_attestation_signing_alg_values_supported: [
        "ES256",
        "ES384",
        "ES512",
      ],
      client_registration_types_supported: ["automatic"],
      code_challenge_methods_supported: ["S256"],
      dpop_signing_alg_values_supported: ["ES256", "ES384", "ES512"],
      grant_types_supported: ["authorization_code"],
      issuer: baseURL,
      jwks: {
        keys: [jwksRepository.getSign().public],
      },
      pushed_authorization_request_endpoint: `${baseURL}/as/par`,
      request_object_signing_alg_values_supported: ["ES256", "ES384", "ES512"],
      require_signed_request_object: true,
      response_types_supported: ["code"],
      scopes_supported: [pidIdentification],
      token_endpoint: `${baseURL}/token`,
      token_endpoint_auth_methods_supported: ["attest_jwt_client_auth"],
      token_endpoint_auth_signing_alg_values_supported: [
        "ES256",
        "ES384",
        "ES512",
      ],
    },
    openid_credential_issuer: {
      client_registration_types_supported: ["automatic"],
      ...createCredentialIssuerMetadataV1_3(baseURL, jwksRepository),
    },
    openid_credential_verifier: {
      application_type: "web",
      client_id: baseURL,
      client_name: "PagoPa S.p.A.",
      encrypted_response_enc_values_supported: ["A128CBC-HS256"],
      jwks: {
        keys: verifierPublicKeys,
      },
      logo_uri: "https://io.italia.it/assets/img/io-it-logo-blue.svg",
      request_uris: [`${baseURL}/authorize`],
      response_uris: [`${baseURL}/presentation-response`],
      vp_formats_supported: {
        "dc+sd-jwt": {
          "kb-jwt_alg_values": ["ES256", "ES384", "ES512"],
          "sd-jwt_alg_values": ["ES256", "ES384", "ES512"],
        },
        mso_mdoc: {
          deviceauth_alg_values: [-9, -50],
          issuerauth_alg_values: [-9, -50],
        },
      },
    },
  } satisfies MetadataV1_3;

  const parsedMetadata = itWalletMetadataV1_3.safeParse(metadata);
  if (!parsedMetadata.success) {
    throw new ValidationError(
      "Invalid entity configuration metadata",
      parsedMetadata.error,
    );
  }

  return parsedMetadata.data;
};
