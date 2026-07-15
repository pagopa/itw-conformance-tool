import path from 'node:path';

import fp from 'fastify-plugin';

import type { FastifyPluginAsync } from 'fastify';

declare module 'fastify' {
  export interface FastifyInstance {
    x5c: string;
  }
}

const certificatePlugin: FastifyPluginAsync = async (app) => {
  const dataDir = app.config.DATA_DIR;
  const certFilePath = path.join(dataDir, 'rp', 'x5c-cert.pem');
  app.decorate('x5c', certFilePath);
};

export default fp(certificatePlugin, {
  name: 'certificate-plugin',
  dependencies: ['config']
});
