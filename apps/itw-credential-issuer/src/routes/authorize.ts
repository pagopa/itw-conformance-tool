import { AuthorizationRequestError, AuthorizationService } from '@itw-conformance-tool/issuer';

import { makeJwksRepository, makeOauthCallbacks } from '../plugins/issuer-runtime.js';

import type { FastifyPluginAsync } from 'fastify';

const authorizeRoute: FastifyPluginAsync = async (app) => {
  const rateLimit = app.rateLimit({ max: 100, timeWindow: '15 minutes' });
  app.route({
    url: '/authorize',
    method: 'GET',
    onRequest: [rateLimit],
    schema: {
      tags: ['Authorization'],
      querystring: {
        type: 'object',
        required: ['client_id', 'request_uri'],
        properties: {
          client_id: { type: 'string' },
          request_uri: { type: 'string' }
        }
      }
    },
    handler: async (request, reply) => {
      const query = request.query as { client_id: string; request_uri: string };
      const { baseURL, oauthCallbacks, sdkConfig } = makeOauthCallbacks(app, request);

      try {
        const service = new AuthorizationService(app.parRepository, makeJwksRepository(app));
        const result = await service.authorize({
          baseURL,
          callbacks: {
            encryptJwe: oauthCallbacks.encryptJwe
          },
          clientId: query.client_id,
          config: sdkConfig,
          requestUri: query.request_uri
        });

        if (result.kind === 'redirect') {
          return reply.code(302).header('Location', result.location).send();
        }

        return reply.code(200).header('Content-Type', 'application/oauth-authz-req+jwt').send(result.payload);
      } catch (error) {
        if (error instanceof AuthorizationRequestError) {
          if (error.redirectUri) {
            const params = new URLSearchParams({
              error: 'invalid_request',
              error_description: error.message,
              ...(error.state ? { state: error.state } : {})
            });
            const location = `${error.redirectUri}?${params.toString()}`;
            return reply.code(302).header('Location', location).send();
          }

          return reply.code(error.statusCode).send({
            error: 'invalid_request',
            error_description: error.message
          });
        }

        request.log.error({ err: error }, 'Authorization request failed');
        return reply.code(500).send({ error: 'internal_server_error' });
      }
    }
  });
};

export default authorizeRoute;
