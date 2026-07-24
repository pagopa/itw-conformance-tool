import { loadConfig } from '@itw-conformance-tool/config';
import { trimTrailingSlashes } from '@itw-conformance-tool/utils';
import fp from 'fastify-plugin';

declare module 'fastify' {
  interface FastifyInstance {
    config: {
      baseUrl: string;
      dataDir: string;
      trustAnchorEntityId: string;
      walletName: string;
    };
  }
}

export default fp(
  async function configPlugin(app) {
    const config = loadConfig();

    app.decorate('config', {
      baseUrl: config['wallet-provider'].local_url,
      dataDir: config.global.data_dir,
      trustAnchorEntityId: trimTrailingSlashes(config['trust-anchor'].url.trim()),
      walletName: config.wallet.wallet_name
    });
  },
  { name: 'config' }
);
