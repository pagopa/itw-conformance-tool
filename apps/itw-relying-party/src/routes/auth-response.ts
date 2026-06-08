import { parseAuthorizationResponseUseCase } from '../use-cases/parse-authorization-response.js';
import { verifyAuthorizationResponseUseCase } from '../use-cases/verify-authorization-response.js';

import type { FastifyPluginAsync } from 'fastify';

const authResponseRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/auth/response',
    method: 'POST',
    schema: {
      tags: ['Relying Party']
    },
    handler: async (request, reply) => {
      const parsedBody = parseAuthorizationResponseUseCase(request.body);

      if (parsedBody.kind === 'oauth-error') {
        try {
          await app.sessionService.update(parsedBody.state, 'rejected');
        } catch {
          // Ignore unknown sessions for OAuth error callbacks.
        }
        return reply.code(200).send({});
      }

      const result = await verifyAuthorizationResponseUseCase({
        baseUrl: app.config.baseUrl,
        jarmResponse: parsedBody.response,
        nonceRepository: app.nonceRepository,
        privateKeyPem: app.rpKeys.authResponsePrivateKeyPem,
        sessionService: app.sessionService,
        trustChain: app.trustChain
      });

      return reply.code(200).send({ redirect_uri: result.redirectUri });
    }
  });
};

export default authResponseRoute;
