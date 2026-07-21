import { loadConfig } from '@itw-conformance-tool/config';
import { trimTrailingSlashes } from '@itw-conformance-tool/utils';
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

export default fp(
  async function configPlugin(app) {
    const config = loadConfig();
    const trustAnchorConfig = config['trust-anchor'];
    const issuerConfig = config['credential-issuer'];
    const rpConfig = config['relying-party'];

    app.decorate('config', {
      baseUrl: trustAnchorConfig.url,
      dataDir: config.global.data_dir,
      issuerEntityId: trimTrailingSlashes(issuerConfig.url.trim()),
      rpEntityId: trimTrailingSlashes(rpConfig.url.trim())
    });
  },

  { name: 'config' }
);
