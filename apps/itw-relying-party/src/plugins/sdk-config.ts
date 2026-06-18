import { IoWalletSdkConfig, ItWalletSpecsVersion } from '@pagopa/io-wallet-utils';
import fp from 'fastify-plugin';

declare module 'fastify' {
  interface FastifyInstance {
    sdkConfig: IoWalletSdkConfig<ItWalletSpecsVersion.V1_4>;
  }
}

export default fp(
  async function sdkConfigPlugin(app) {
    app.decorate(
      'sdkConfig',
      new IoWalletSdkConfig({
        itWalletSpecsVersion: ItWalletSpecsVersion.V1_4
      })
    );
  },
  { name: 'sdk-config-plugin' }
);
