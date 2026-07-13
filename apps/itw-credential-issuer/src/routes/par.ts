import { PARService, PostPushedAuthorizationError } from '../domain/index.js';
import { makeOauthCallbacks } from '../plugins/index.js';

import type { HttpMethod } from '@pagopa/io-wallet-utils';
import type { FastifyPluginAsync } from 'fastify';

const parRoute: FastifyPluginAsync = async (app) => {
  app.route<{ Body: Record<string, string> }>({
    url: '/as/par',
    method: 'POST',
    schema: {
      tags: ['Authorization']
    },
    handler: async (request, reply) => {
      const bodyString = new URLSearchParams(request.body).toString();

      const { baseURL, headers, jwksRepository, oauthCallbacks, sdkConfig } = makeOauthCallbacks(app, request);

      try {
        const service = new PARService(app.parRepository);
        const requestUri = await service.parseAndStore({
          baseURL,
          callbacks: {
            fetch: oauthCallbacks.fetch,
            hash: oauthCallbacks.hash,
            verifyJwt: oauthCallbacks.verifyJwt
          },
          config: sdkConfig,
          jwksRepository,
          parRequest: {
            bodyString,
            headers,
            method: request.method as HttpMethod,
            url: `${baseURL}${request.url}`
          }
        });

        return reply.code(201).send({
          expires_in: 60,
          request_uri: requestUri
        });
      } catch (error) {
        if (error instanceof PostPushedAuthorizationError) {
          return reply.code(400).send({
            error: 'invalid_request',
            error_description: error.message
          });
        }

        if (error instanceof Error && error.name === 'Oauth2JwtParseError') {
          return reply.code(400).send({
            error: 'invalid_request',
            error_description: error.message
          });
        }

        request.log.error({ err: error }, 'PAR request failed');
        return reply.code(500).send({ error: 'internal_server_error' });
      }
    }
  });
};

export default parRoute;
