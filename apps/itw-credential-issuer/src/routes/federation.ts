import { createObservedEvent } from '@itw-conformance-tool/conformance';

import { FederationService } from '../domain/index.js';
import { makeJwksRepository, makeOauthCallbacks } from '../plugins/index.js';

import type { FastifyPluginAsync } from 'fastify';

const federationRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/.well-known/openid-federation',
    method: 'GET',
    schema: {
      tags: ['Federation']
    },
    handler: async (request, reply) => {
      const { baseURL, sdkConfig } = makeOauthCallbacks(app, request);

      try {
        const service = new FederationService(makeJwksRepository(app));
        const statement = await service.getEntityConfiguration(baseURL, sdkConfig, app.config.TRUST_ANCHOR_ENTITY_ID);

        await app.conformanceEventSink?.emit(
          createObservedEvent({
            name: 'issuer.entity_configuration.requested',
            correlationId: request.conformance?.correlation?.correlationId ?? null,
            service: 'credential-issuer',
            requestId: request.id,
            diagnostic: {
              endpoint: '/.well-known/openid-federation'
            }
          })
        );

        return reply.code(200).header('Content-Type', 'application/entity-statement+jwt').send(statement);
      } catch (error) {
        request.log.error({ err: error }, 'OpenID federation metadata generation failed');
        return reply.code(500).send({ error: 'internal_server_error' });
      }
    }
  });
};

export default federationRoute;
