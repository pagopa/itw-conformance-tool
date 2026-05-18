import { PARService, PostPushedAuthorizationError } from '@itw-conformance-tool/issuer';

import { makeOauthCallbacks } from '../plugins/issuer-runtime.js';

import type { HttpMethod } from '@pagopa/io-wallet-utils';
import type { FastifyPluginAsync } from 'fastify';

const parRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/as/par',
    method: 'POST',
    config: {
      rateLimit: {
        max: 100,
        timeWindow: '15 minutes'
      }
    },
    preHandler: app.rateLimit({ max: 100, timeWindow: '15 minutes' }),
    schema: {
      tags: ['Authorization']
    },
    handler: async (request, reply) => {
      const bodyString = typeof request.body === 'string' ? request.body : '';
      const { baseURL, headers, oauthCallbacks, sdkConfig } = makeOauthCallbacks(app, request);

      try {
        const service = new PARService(app.parRepository);
        const requestUri = await service.parseAndStore({
          baseURL,
          callbacks: { fetch: oauthCallbacks.fetch },
          config: sdkConfig,
          parRequest: {
            bodyString,
            headers,
            method: request.method as HttpMethod,
            url: request.url
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

        request.log.error({ err: error }, 'PAR request failed');
        return reply.code(500).send({ error: 'internal_server_error' });
      }
    }
  });
};

export default parRoute;
