import type { DcqlQuery } from "dcql";

import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";

export const getDcqlQuery = (config: IoWalletSdkConfig): DcqlQuery => ({
  credentials: [
    {
      claims: [
        {
          id: "family_name",
          path: ["family_name"],
        },
        {
          id: "given_name",
          path: ["given_name"],
        },
        {
          id: config.isVersion(ItWalletSpecsVersion.V1_3)
            ? "birthdate"
            : "birth_date",
          path: config.isVersion(ItWalletSpecsVersion.V1_3)
            ? ["birthdate"]
            : ["birth_date"],
        },
        {
          id: config.isVersion(ItWalletSpecsVersion.V1_3)
            ? "place_of_birth"
            : "birth_place",
          path: config.isVersion(ItWalletSpecsVersion.V1_3)
            ? ["place_of_birth"]
            : ["birth_place"],
        },
        {
          id: "nationalities",
          path: ["nationalities"],
        },
      ],
      format: "dc+sd-jwt",
      id: "0",
      meta: {
        vct_values: config.isVersion(ItWalletSpecsVersion.V1_3)
          ? ["urn:eudi:pid:it:1"]
          : [
              "eu.europa.ec.eudi.pid.1",
              "urn:eu.europa.ec.eudi:pid:1",
              "https://pre.ta.wallet.ipzs.it/vct/v1.0.0/personidentificationdata",
            ],
      },
      multiple: false,
      require_cryptographic_holder_binding: true,
    },
  ],
});
