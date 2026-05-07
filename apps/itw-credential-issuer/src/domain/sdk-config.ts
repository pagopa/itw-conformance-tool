import {
  IoWalletSdkConfig,
  ItWalletSpecsVersion,
} from "@pagopa/io-wallet-utils";

const sdkConfigs = {
  [ItWalletSpecsVersion.V1_0]: new IoWalletSdkConfig({
    itWalletSpecsVersion: ItWalletSpecsVersion.V1_0,
  }),
  [ItWalletSpecsVersion.V1_3]: new IoWalletSdkConfig({
    itWalletSpecsVersion: ItWalletSpecsVersion.V1_3,
  }),
} as const satisfies Record<ItWalletSpecsVersion, IoWalletSdkConfig>;

export const getSdkConfig = (
  specVersion: ItWalletSpecsVersion,
): IoWalletSdkConfig => sdkConfigs[specVersion];
