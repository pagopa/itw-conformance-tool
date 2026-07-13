import { loadConfig, type IssuerAuthFlow } from '@itw-conformance-tool/config';
import fp from 'fastify-plugin';

declare module 'fastify' {
  interface FastifyInstance {
    config: {
      BASE_URL: string;
      DATA_DIR: string;
      AUTH_FLOW: IssuerAuthFlow;
    };
  }
}

export default fp(
  async function configPlugin(app) {
    const config = loadConfig();
    const issuerConfig = config['itw-credential-issuer'];

    app.decorate('config', {
      AUTH_FLOW: issuerConfig.auth_flow,
      BASE_URL: `https://localhost:${issuerConfig.port}`,
      DATA_DIR: config.global.data_dir
    });
  },

  { name: 'config' }
);
