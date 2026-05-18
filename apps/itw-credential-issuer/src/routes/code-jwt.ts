import { CodeJwtService, InvalidRequestUriError } from '@itw-conformance-tool/issuer';

import { makeCodeJwtParRepository, makeJwksRepository, makeOauthCallbacks } from '../plugins/issuer-runtime.js';

import type { FastifyPluginAsync } from 'fastify';

const codeJwtRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/code/jwt',
    method: 'GET',
    config: {
      rateLimit: {
        max: 30,
        timeWindow: '1 minute'
      }
    },
    preHandler: app.rateLimit({ max: 30, timeWindow: '1 minute' }),
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
      const requestUri = (request.query as { request_uri: string }).request_uri;
      const { baseURL } = makeOauthCallbacks(app, request);

      try {
        const service = new CodeJwtService({
          baseURL,
          jwksRepository: makeJwksRepository(app),
          parRepository: makeCodeJwtParRepository(app)
        });

        const result = await service.createAuthorizationCodeJwt(requestUri);
        return reply.code(200).header('Content-Type', 'text/html').send(result.formPost);
      } catch (error) {
        if (error instanceof InvalidRequestUriError) {
          return reply.code(400).send({ error: 'invalid_request', error_description: error.message });
        }

        request.log.error({ err: error }, 'Authorization code JWT generation failed');
        return reply.code(500).send({ error: 'internal_server_error' });
      }
    }
  });
};

export default codeJwtRoute;
