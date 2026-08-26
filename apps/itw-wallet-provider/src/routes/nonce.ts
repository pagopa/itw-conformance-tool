import type { FastifyPluginAsync } from 'fastify';

const nonceRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/nonce',
    method: 'GET',
    schema: {
      operationId: 'getWalletNonce',
      summary: 'Retrieve a Wallet Solution nonce',
      description: 'Returns a cryptographically random, single-use nonce for Wallet Instance initialization.',
      tags: ['Wallet Solution'],
      produces: ['application/json'],
      response: {
        200: {
          type: 'object',
          required: ['nonce'],
          properties: {
            nonce: { type: 'string' }
          }
        }
      }
    },
    handler: async (_request, reply) => {
      const nonce = app.walletNonces.issue();
      return reply.code(200).header('cache-control', 'no-store').send({ nonce });
    }
  });
};

export default nonceRoute;
