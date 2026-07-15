import path from 'node:path';

import { loadConfig } from '@itw-conformance-tool/config';
import fp from 'fastify-plugin';

import type { FastifyPluginAsync } from 'fastify';

declare module 'fastify' {
  interface FastifyInstance {
    config: {
      BASE_URL: string;
      DATA_DIR: string;
      IACA_X509: string;
    };
  }
}

const configPlugin: FastifyPluginAsync = async (app) => {
  const config = loadConfig();
  const relyingPartyConfig = config['relying-party'];

  const dataDir = config.global.data_dir;
  const certFilePath = path.join(dataDir, 'rp', 'x5c-cert.pem');

  app.decorate('config', {
    BASE_URL: relyingPartyConfig.url,
    DATA_DIR: dataDir,
    IACA_X509: certFilePath
  });
};

export default fp(configPlugin, { name: 'config' });
