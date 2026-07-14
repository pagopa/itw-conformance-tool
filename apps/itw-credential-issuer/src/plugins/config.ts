import { loadConfig, type IssuerAuthFlow } from '@itw-conformance-tool/config';
import fp from 'fastify-plugin';

declare module 'fastify' {
  interface FastifyInstance {
    config: {
      BASE_URL: string;
      DATA_DIR: string;
      AUTH_FLOW: IssuerAuthFlow;
      BATCH_ISSUANCE_BY_DEFERRED: boolean;
    };
  }
}

export default fp(
  async function configPlugin(app) {
    const config = loadConfig();
    const issuerConfig = config['credential-issuer'];

    app.decorate('config', {
      AUTH_FLOW: issuerConfig.auth_flow,
      BASE_URL: issuerConfig.url,
      BATCH_ISSUANCE_BY_DEFERRED: issuerConfig.batch_issuance_by_deferred,
      DATA_DIR: config.global.data_dir
    });
  },

  { name: 'config' }
);
