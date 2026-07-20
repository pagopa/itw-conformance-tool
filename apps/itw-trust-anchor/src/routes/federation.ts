import { createTrustAnchorEntityConfiguration } from '../federation/statements.js';

import type { FastifyPluginAsync } from 'fastify';

const federationRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/.well-known/openid-federation',
    method: 'GET',
    schema: {
      tags: ['Federation']
    },
    handler: async (request, reply) => {
      try {
        const entityConfiguration = await createTrustAnchorEntityConfiguration({
          federationPrivateJwk: app.trustAnchorKeys.federationPrivateJwk,
          issuerEntityId: app.config.issuerEntityId,
          relyingPartyEntityId: app.config.rpEntityId,
          trustAnchorBaseUrl: app.config.baseUrl
        });

        return reply.code(200).header('Content-Type', 'application/entity-statement+jwt').send(entityConfiguration);
      } catch (error) {
        request.log.error({ err: error }, 'Trust Anchor entity configuration generation failed');
        return reply.code(500).send({ error: 'internal_server_error' });
      }
    }
  });
};

export default federationRoute;
