import type { JwksRepository } from "@/domain/signer";
import type { ItWalletCredentialIssuerMetadata } from "@pagopa/io-wallet-oid-federation";

import { itWalletCredentialIssuerMetadata } from "@pagopa/io-wallet-oid-federation";
import { ItWalletSpecsVersion, ValidationError } from "@pagopa/io-wallet-utils";

import {
  dc_sd_jwt_EuropeanDisabilityCard,
  dc_sd_jwt_PersonIdentificationData,
  mso_mdoc_PersonIdentificationData,
  mso_mdoc_mDL,
} from "../shared/credential-configurations";

export const createCredentialIssuerMetadataV1_0 = (
  baseURL: string,
  jwksRepository: JwksRepository,
): ItWalletCredentialIssuerMetadata => {
  const metadata = {
    batch_credential_issuance: {
      batch_size: 30,
    },
    credential_configurations_supported: {
      dc_sd_jwt_EuropeanDisabilityCard:
        dc_sd_jwt_EuropeanDisabilityCard(baseURL),
      dc_sd_jwt_PersonIdentificationData: dc_sd_jwt_PersonIdentificationData(
        baseURL,
        ItWalletSpecsVersion.V1_0,
      ),
      mso_mdoc_PersonIdentificationData: mso_mdoc_PersonIdentificationData(
        baseURL,
        ItWalletSpecsVersion.V1_0,
      ),
      "org.iso.18013.5.1.mDL": mso_mdoc_mDL(baseURL),
    },
    credential_endpoint: `${baseURL}/credential`,
    credential_hash_alg_supported: "sha-256",
    credential_issuer: baseURL,
    deferred_credential_endpoint: `${baseURL}/deferred`,
    display: [
      {
        background_color: "#12107c",
        locale: "it-IT",
        logo: {
          alt_text: "logo",
          url: "https://io.italia.it/assets/img/io-it-logo-blue.svg",
        },
        name: "PagoPA S.p.A.",
        text_color: "#FFFFFF",
      },
    ],
    evidence_supported: ["vouch"],
    jwks: {
      keys: [jwksRepository.getSign().public],
    },
    nonce_endpoint: `${baseURL}/nonce`,
    notification_endpoint: `${baseURL}/notification`,
    revocation_endpoint: `${baseURL}/revoke`,
    status_assertion_endpoint: `${baseURL}/status`,
    status_attestation_endpoint: `${baseURL}/status`,
    trust_frameworks_supported: ["it_cie", "eudi_wallet", "it_wallet"],
  };

  const parsedMetadata = itWalletCredentialIssuerMetadata.safeParse(metadata);
  if (!parsedMetadata.success) {
    throw new ValidationError(
      "Invalid credential issuer metadata",
      parsedMetadata.error,
    );
  }

  return parsedMetadata.data;
};
