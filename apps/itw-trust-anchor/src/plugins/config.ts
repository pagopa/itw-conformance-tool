import { loadConfig } from '@itw-conformance-tool/config';
import fp from 'fastify-plugin';

declare module 'fastify' {
  interface FastifyInstance {
    config: {
      baseUrl: string;
      dataDir: string;
      issuerEntityId: string;
      rpEntityId: string;
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
    const trustAnchorConfig = config['trust-anchor'];
    const issuerConfig = config['credential-issuer'];
    const rpConfig = config['relying-party'];

    app.decorate('config', {
      baseUrl: trustAnchorConfig.url,
      dataDir: config.global.data_dir,
      issuerEntityId: trimTrailingSlashes(issuerConfig.entity_id.trim()),
      rpEntityId: trimTrailingSlashes(rpConfig.entity_id.trim())
    });
  },

  { name: 'config' }
);
