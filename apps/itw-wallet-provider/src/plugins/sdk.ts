import { WalletProvider } from '@pagopa/io-wallet-oid4vci';
import { IoWalletSdkConfig, ItWalletSpecsVersion } from '@pagopa/io-wallet-utils';
import fp from 'fastify-plugin';

import type { FastifyInstance } from 'fastify';

declare module 'fastify' {
  interface FastifyInstance {
    walletProvider: WalletProvider;
    sdkConfig: IoWalletSdkConfig<ItWalletSpecsVersion.V1_4>;
  }
}

export default fp(
  async function sdkPlugin(app: FastifyInstance) {
    const sdkConfig = new IoWalletSdkConfig({ itWalletSpecsVersion: ItWalletSpecsVersion.V1_4 });

    app.decorate('sdkConfig', sdkConfig);
    app.decorate('walletProvider', new WalletProvider(sdkConfig));
  },
  { name: 'sdk' }
);
