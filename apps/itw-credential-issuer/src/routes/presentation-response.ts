import { PresentationResponseError, PresentationResponseService } from '@itw-conformance-tool/issuer';

import { makeJwksRepository, makeOauthCallbacks } from '../plugins/issuer-runtime.js';

import type { FastifyPluginAsync } from 'fastify';

const presentationResponseRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/presentation-response',
    method: 'POST',
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
      const bodyString = typeof request.body === 'string' ? request.body : '';
      const { baseURL, oauthCallbacks } = makeOauthCallbacks(app, request);

      try {
        const service = new PresentationResponseService(app.parRepository, makeJwksRepository(app));
        const result = await service.handle({
          baseURL,
          callbacks: {
            verifyJwt: oauthCallbacks.verifyJwt
          },
          bodyString,
          requestUri: query.request_uri
        });

        return reply.code(200).send({ redirect_uri: result.redirectUri });
      } catch (error) {
        if (error instanceof PresentationResponseError) {
          return reply.code(error.statusCode).send({
            error: 'invalid_request',
            error_description: error.message
          });
        }

        request.log.error({ err: error }, 'Presentation response processing failed');
        return reply.code(500).send({ error: 'internal_server_error' });
      }
    }
  });
};

export default presentationResponseRoute;
