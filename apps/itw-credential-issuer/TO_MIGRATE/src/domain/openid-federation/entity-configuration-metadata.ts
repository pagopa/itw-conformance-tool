import type { JwksRepository } from "@/domain/signer";
import type { ItWalletEntityConfigurationClaimsOptions } from "@pagopa/io-wallet-oid-federation";

import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";

import { getEntityConfigurationClaimsMetadataV1_0 } from "./v1.0/entity-configuration-metadata";
import { getEntityConfigurationClaimsMetadataV1_3 } from "./v1.3/entity-configuration-metadata";

export const getEntityConfigurationClaimsMetadata = (
  baseURL: string,
  jwksRepository: JwksRepository,
  config: IoWalletSdkConfig,
): ItWalletEntityConfigurationClaimsOptions["metadata"] => {
  if (config.isVersion(ItWalletSpecsVersion.V1_3)) {
    return getEntityConfigurationClaimsMetadataV1_3(baseURL, jwksRepository);
  }

  return getEntityConfigurationClaimsMetadataV1_0(baseURL, jwksRepository);
};
