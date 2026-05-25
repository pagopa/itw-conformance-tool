import { FederationService } from '@itw-conformance-tool/issuer';

import { makeJwksRepository, makeOauthCallbacks } from '#/plugins/index.js';

import type { FastifyPluginAsync } from 'fastify';

const federationRoute: FastifyPluginAsync = async (app) => {
  const rateLimit = app.rateLimit({ max: 100, timeWindow: '15 minutes' });
  app.route({
    url: '/.well-known/openid-federation',
    method: 'GET',
    onRequest: [rateLimit],
    schema: {
      tags: ['Federation']
    },
    handler: async (request, reply) => {
      const { baseURL, sdkConfig } = makeOauthCallbacks(app, request);

      try {
        const service = new FederationService(makeJwksRepository(app));
        const statement = await service.getEntityConfiguration(baseURL, sdkConfig);

        return reply.code(200).header('Content-Type', 'application/entity-statement+jwt').send(statement);
      } catch (error) {
        request.log.error({ err: error }, 'OpenID federation metadata generation failed');
        return reply.code(500).send({ error: 'internal_server_error' });
      }
    }
  });
};

export default federationRoute;
