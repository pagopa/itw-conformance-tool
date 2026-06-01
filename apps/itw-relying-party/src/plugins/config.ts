import { resolve } from 'node:path';

import { loadRpConfig } from '@itw-conformance-tool/rp';
import fp from 'fastify-plugin';

declare module 'fastify' {
  interface FastifyInstance {
    config: {
      host: string;
      port: number;
      baseUrl: string;
      entityId: string;
      trustAnchorUrl?: string;
      dataDir: string;
      configFilePath: string;
    };
  }
}

export default fp(
  async function configPlugin(app) {
    const configFilePath = resolve(process.cwd(), process.env.ITW_CT_CONFIG_FILE ?? 'config.ini');
    const { config } = loadRpConfig({ configFilePath });

    app.decorate('config', {
      host: config.host,
      port: config.port,
      baseUrl: config.baseUrl,
      entityId: config.entityId,
      trustAnchorUrl: config.trustAnchorUrl,
      dataDir: config.dataDir,
      configFilePath
    });
  },
  { name: 'config' }
);
