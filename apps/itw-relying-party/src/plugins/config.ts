import { loadRpConfig } from '@itw-conformance-tool/rp';
import fp from 'fastify-plugin';

declare module 'fastify' {
  interface FastifyInstance {
    config: {
      url: string;
      entityId: string;
      dataDir: string;
      configFilePath: string;
      trustAnchorUrl?: string;
      x5cCertPath: string;
    };
  }
}

export default fp(
  async function configPlugin(app) {
    const { config } = loadRpConfig();

    app.decorate('config', {
      url: config.url,
      entityId: config.entityId,
      trustAnchorUrl: config.trustAnchorUrl,
      dataDir: config.dataDir,
      configFilePath: config.configFilePath,
      x5cCertPath: config.x5cCertPath
    });
  },
  { name: 'config' }
);
