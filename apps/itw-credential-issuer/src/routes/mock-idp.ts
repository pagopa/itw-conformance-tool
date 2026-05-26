import { makeJwksRepository, makeOauthCallbacks } from '../plugins/index.js';
import { MockIdpRequestError, MockIdpService } from '../services/mock-idp-service.js';

import type { FastifyPluginAsync } from 'fastify';

const mockIdpAuthorizeRoute: FastifyPluginAsync = async (app) => {
  const rateLimit = app.rateLimit({ max: 100, timeWindow: '15 minutes' });

  app.route({
    url: '/idp/authorize',
    method: 'GET',
    onRequest: [rateLimit],
    schema: {
      tags: ['Authorization'],
      querystring: {
        type: 'object',
        required: ['request_uri'],
        properties: {
          request_uri: { type: 'string' }
        }
      }
    },
    handler: async (request, reply) => {
      const query = request.query as { request_uri: string };
      const { baseURL } = makeOauthCallbacks(app, request);

      try {
        const service = new MockIdpService(app.parRepository, makeJwksRepository(app));
        const result = await service.authorize({
          baseURL,
          requestUri: query.request_uri
        });

        return reply.code(302).header('Location', result.location).send();
      } catch (error) {
        if (error instanceof MockIdpRequestError) {
          return reply.code(error.statusCode).send({
            error: 'invalid_request',
            error_description: error.message
          });
        }

        request.log.error({ err: error }, 'Mock IdP authorization failed');
        return reply.code(500).send({ error: 'internal_server_error' });
      }
    }
  });
};

export default mockIdpAuthorizeRoute;
