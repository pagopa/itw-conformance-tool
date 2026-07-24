import { createObservedEvent } from '@itw-conformance-tool/conformance';

import { AuthorizationRequestError, AuthorizationService } from '../domain/index.js';
import { makeJwksRepository, makeOauthCallbacks } from '../plugins/index.js';

import type { FastifyPluginAsync } from 'fastify';

const authorizeRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/authorize',
    method: 'GET',
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
          authFlow: app.config.AUTH_FLOW,
          baseURL,
          callbacks: {
            encryptJwe: oauthCallbacks.encryptJwe
          },
          clientId: query.client_id,
          config: sdkConfig,
          requestUri: query.request_uri,
          trustAnchorEntityId: app.config.TRUST_ANCHOR_ENTITY_ID
        });

        await app.conformanceEventSink?.emit(
          createObservedEvent({
            name: 'issuer.authorization.requested',
            correlationId: request.conformance?.correlation?.correlationId ?? null,
            service: 'credential-issuer',
            requestId: request.id,
            diagnostic: {
              endpoint: '/authorize',
              clientId: query.client_id,
              requestUri: query.request_uri
            }
          })
        );

        if (result.kind === 'redirect') {
          return reply.code(302).header('Location', result.location).send();
        }

        return reply.code(200).header('Content-Type', 'application/oauth-authz-req+jwt').send(result.payload);
      } catch (error) {
        if (error instanceof AuthorizationRequestError) {
          if (error.redirectUri) {
            const location = new URL(error.redirectUri);
            location.searchParams.set('error', 'invalid_request');
            location.searchParams.set('error_description', error.message);
            if (error.state) {
              location.searchParams.set('state', error.state);
            }
            return reply.code(302).header('Location', location.toString()).send();
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
