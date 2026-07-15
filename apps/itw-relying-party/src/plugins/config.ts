import { loadConfig } from '@itw-conformance-tool/config';
import fp from 'fastify-plugin';

import type { FastifyPluginAsync } from 'fastify';

declare module 'fastify' {
  interface FastifyInstance {
    config: {
      BASE_URL: string;
      DATA_DIR: string;
    };
  }
}

const configPlugin: FastifyPluginAsync = async (app) => {
  const config = loadConfig();
  const relyingPartyConfig = config['relying-party'];

  app.decorate('config', {
    BASE_URL: relyingPartyConfig.url,
    DATA_DIR: config.global.data_dir
  });
};

export default fp(configPlugin, { name: 'config' });
