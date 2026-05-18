import { NonceService } from '@itw-conformance-tool/issuer';

import type { FastifyPluginAsync } from 'fastify';

const nonceRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/nonce',
    method: 'POST',
    config: {
      rateLimit: {
        max: 100,
        timeWindow: '15 minutes'
      }
    },
    preHandler: app.rateLimit({ max: 100, timeWindow: '15 minutes' }),
    schema: {
      tags: ['Credential']
    },
    handler: async (_request, reply) => {
      try {
        const service = new NonceService(app.nonceRepository);
        const nonce = await service.generate();

        return reply
          .code(200)
          .headers({
            'Cache-Control': 'no-store',
            'Content-Type': 'application/json'
          })
          .send({ c_nonce: nonce });
      } catch (error) {
        app.log.error({ err: error }, 'Nonce generation failed');
        return reply.code(500).send({ error: 'internal_server_error' });
      }
    }
  });
};

export default nonceRoute;
