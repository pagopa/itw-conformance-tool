import { createNonce } from '../wallet-provider-backend/service.js';

import type { FastifyPluginAsync } from 'fastify';

const nonceRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/nonce',
    method: 'GET',
    schema: {
      tags: ['Wallet Provider']
    },
    handler: async (_request, reply) => {
      const body = createNonce(app.walletProviderBackend);
      return reply.code(200).header('Content-Type', 'application/json').send(body);
    }
  });
};

export default nonceRoute;
