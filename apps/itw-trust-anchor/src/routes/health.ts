import type { FastifyPluginAsync } from 'fastify';

const healthRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/health',
    method: 'GET',
    schema: {
      tags: ['Health']
    },
    handler: async () => {
      return { status: 'ok' };
    }
  });
};

export default healthRoute;
