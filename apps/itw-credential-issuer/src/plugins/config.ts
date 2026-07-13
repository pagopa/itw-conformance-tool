import { loadConfig, type IssuerAuthFlow } from '@itw-conformance-tool/config';
import fp from 'fastify-plugin';

declare module 'fastify' {
  interface FastifyInstance {
    config: {
      BASE_URL: string;
      DATA_DIR: string;
      AUTH_FLOW: IssuerAuthFlow;
      TRUST_ANCHOR_ENTITY_ID: string;
    };
  }
}

function trimTrailingSlashes(value: string): string {
  let result = value;
  while (result.endsWith('/')) {
    result = result.slice(0, -1);
  }
  return result;
}

export default fp(
  async function configPlugin(app) {
    const config = loadConfig();
    const issuerConfig = config['credential-issuer'];

    app.decorate('config', {
      AUTH_FLOW: issuerConfig.auth_flow,
      BASE_URL: issuerConfig.url,
      DATA_DIR: config.global.data_dir,
      TRUST_ANCHOR_ENTITY_ID: trimTrailingSlashes(issuerConfig.trust_anchor_url.trim())
    });
  },

  { name: 'config' }
);
