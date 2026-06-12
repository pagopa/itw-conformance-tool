import { createEntityConfigurationJwt } from '../federation/entity-configuration.js';

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
        const entityStatement = await createEntityConfigurationJwt({
          entityId: app.config.entityId,
          trustAnchorUrl: app.config.trustAnchorUrl,
          authRequestPrivateKeyPem: app.rpKeys.authRequestPrivateKeyPem,
          authResponsePrivateKeyPem: app.rpKeys.authResponsePrivateKeyPem,
          x5cCertPem: app.rpKeys.x5cCertPem
        });

        return reply.code(200).header('Content-Type', 'application/entity-statement+jwt').send(entityStatement);
      } catch (error) {
        request.log.error({ err: error }, 'OpenID federation metadata generation failed');
        return reply.internalServerError('Failed to generate OpenID federation metadata');
      }
    }
  });
};

export default federationRoute;
