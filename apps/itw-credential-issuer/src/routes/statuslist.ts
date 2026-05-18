import { StatusListService } from '@itw-conformance-tool/issuer';

import { makeJwksRepository, makeOauthCallbacks } from '../plugins/issuer-runtime.js';

import type { FastifyPluginAsync } from 'fastify';

const statusListRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/statuslist/1',
    method: 'GET',
    config: {
      rateLimit: {
        max: 100,
        timeWindow: '15 minutes'
      }
    },
    schema: {
      tags: ['Credential']
    },
    handler: async (request, reply) => {
      const { baseURL } = makeOauthCallbacks(app, request);

      try {
        const service = new StatusListService(makeJwksRepository(app));
        const jwt = await service.getStatusListJwt(baseURL);

        return reply.code(200).header('Content-Type', 'application/statuslist+jwt').send(jwt);
      } catch (error) {
        request.log.error({ err: error }, 'Status list generation failed');
        return reply.code(500).send({ error: 'internal_server_error' });
      }
    }
  });
};

export default statusListRoute;
