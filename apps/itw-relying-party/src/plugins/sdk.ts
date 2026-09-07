import { IoWalletSdkConfig, ItWalletSpecsVersion } from '@pagopa/io-wallet-utils';
import fp from 'fastify-plugin';

import type { FastifyPluginAsync } from 'fastify';

declare module 'fastify' {
  interface FastifyInstance {
    sdkConfig: IoWalletSdkConfig<ItWalletSpecsVersion.V1_4>;
  }
}

const sdkConfigPlugin: FastifyPluginAsync = async (app) => {
  const sdkConfig = new IoWalletSdkConfig({
    itWalletSpecsVersion: ItWalletSpecsVersion.V1_4
  });

  app.decorate('sdkConfig', sdkConfig);
};

export default fp(sdkConfigPlugin, {
  name: 'sdk-config-plugin'
});
