import {
  CreateAccessTokenError,
  InvalidGrantError,
  TokenService,
  UnsupportedGrantTypeError
} from '@itw-conformance-tool/issuer';

import { makeJwksRepository, makeOauthCallbacks, makeTokenParRepository } from '../plugins/issuer-runtime.js';

import type { FastifyPluginAsync } from 'fastify';

const tokenRoute: FastifyPluginAsync = async (app) => {
  const rateLimit = app.rateLimit({ max: 100, timeWindow: '15 minutes' });
  app.route({
    url: '/token',
    method: 'POST',
    onRequest: [rateLimit],
    schema: {
      tags: ['Authorization']
    },
    handler: async (request, reply) => {
      const bodyString = typeof request.body === 'string' ? request.body : '';
      const { baseURL, oauthCallbacks, sdkConfig } = makeOauthCallbacks(app, request);

      try {
        const service = new TokenService(makeTokenParRepository(app), makeJwksRepository(app));
        const response = await service.createAccessToken({
          baseURL,
          callbacks: {
            generateRandom: oauthCallbacks.generateRandom,
            hash: oauthCallbacks.hash,
            signJwt: oauthCallbacks.signJwt
          },
          config: sdkConfig,
          tokenRequest: {
            bodyString
          }
        });

        return reply
          .code(200)
          .headers({
            'Cache-Control': 'no-store',
            'Content-Type': 'application/json'
          })
          .send(response);
      } catch (error) {
        if (error instanceof CreateAccessTokenError) {
          return reply.code(400).send({ error: 'invalid_request', error_description: error.message });
        }

        if (error instanceof InvalidGrantError) {
          return reply.code(400).send({ error: 'invalid_grant', error_description: error.message });
        }

        if (error instanceof UnsupportedGrantTypeError) {
          return reply.code(400).send({ error: 'unsupported_grant_type', error_description: error.message });
        }

        request.log.error({ err: error }, 'Token request failed');
        return reply.code(500).send({ error: 'internal_server_error' });
      }
    }
  });
};

export default tokenRoute;
