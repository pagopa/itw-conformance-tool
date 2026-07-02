import { createEntityConfigurationJwt } from '../federation/entity-configuration.js';
import { recordFederationFetchAccess } from '../wallet-provider-backend/service.js';

import type { FastifyPluginAsync } from 'fastify';

const fetchRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/fetch',
    method: 'POST',
    schema: {
      tags: ['Wallet Provider']
    },
    handler: async (request, reply) => {
      const body = request.body as { entity_id?: string } | undefined;
      if (!body?.entity_id) {
        return reply
          .code(400)
          .header('Content-Type', 'application/json')
          .send({ error: 'bad_request', error_description: 'entity_id is required' });
      }

      recordFederationFetchAccess(app.walletProviderBackend, request.method, request.url);

      try {
        const entityStatement = await createEntityConfigurationJwt({
          entityId: app.config.baseUrl,
          trustAnchorUrl: app.config.trustAnchorUrl,
          authRequestPrivateKeyPem: app.rpKeys.authRequestPrivateKeyPem,
          authResponsePrivateKeyPem: app.rpKeys.authResponsePrivateKeyPem,
          federationPrivateKeyPem: app.rpKeys.federationPrivateKeyPem,
          x5cCertPem: app.rpKeys.x5cCertPem
        });

        return reply.code(200).header('Content-Type', 'application/entity-statement+jwt').send(entityStatement);
      } catch (error) {
        request.log.error({ err: error }, 'OpenID federation fetch failed');
        return reply.internalServerError('Failed to fetch OpenID federation metadata');
      }
    }
  });
};

export default fetchRoute;
