import { getConformanceDebugSnapshot } from '../wallet-provider-backend/service.js';

import type { FastifyPluginAsync } from 'fastify';

const conformanceDebugRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/conformance/wallet-provider/debug',
    method: 'GET',
    schema: {
      tags: ['Conformance']
    },
    handler: async (_request, reply) => {
      return reply
        .code(200)
        .header('Content-Type', 'application/json')
        .send(getConformanceDebugSnapshot(app.walletProviderBackend));
    }
  });
};

export default conformanceDebugRoute;
