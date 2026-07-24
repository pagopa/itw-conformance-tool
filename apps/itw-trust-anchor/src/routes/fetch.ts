import { createObservedEvent } from '@itw-conformance-tool/conformance';

import { createSubordinate } from '../federation/statements.js';

import type { SubordinateEntityKind } from '../federation/statements.js';
import type { JwkKey } from '../plugins/keys.js';
import type { FastifyPluginAsync, FastifyRequest } from 'fastify';

interface FetchQuerystring {
  sub: string;
}

const fetchRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/fetch',
    method: 'GET',
    schema: {
      tags: ['Federation'],
      // Rejects a missing/empty `sub` as a client error before any signing logic runs.
      querystring: {
        type: 'object',
        required: ['sub'],
        properties: {
          sub: { type: 'string', minLength: 1 }
        }
      }
    },
    handler: async (request: FastifyRequest<{ Querystring: FetchQuerystring }>, reply) => {
      const { sub } = request.query;
      const { baseUrl, issuerEntityId, rpEntityId } = app.config;

      let subjectKind: SubordinateEntityKind;
      let subjectPrivateJwk: JwkKey;

      if (sub === issuerEntityId) {
        subjectKind = 'issuer';
        subjectPrivateJwk = app.trustAnchorKeys.issuerFederationJwk;
      } else if (sub === rpEntityId) {
        subjectKind = 'rp';
        subjectPrivateJwk = app.trustAnchorKeys.rpFederationJwk;
      } else {
        return reply.code(404).send({ error: 'not_found' });
      }

      try {
        const subordinateStatement = await createSubordinate({
          federationPrivateJwk: app.trustAnchorKeys.federationPrivateJwk,
          subjectEntityId: sub,
          subjectKind,
          subjectPrivateJwk,
          trustAnchorBaseUrl: baseUrl
        });

        // The wallet fetches the subordinate statement about the requested
        // entity while resolving its Trust Chain. Both the issuance flow
        // (sub = Credential Issuer) and the presentation flow (sub = Relying
        // Party) rely on this evidence; the `sub` diagnostic lets the scenario
        // narrow adoption to the entity it expects (WP_078 / WP_079 / WP_080).
        await app.conformanceEventSink?.emit(
          createObservedEvent({
            name: 'federation.fetch.requested',
            scenarioId: request.conformance?.correlation?.scenarioId ?? null,
            correlationId: request.conformance?.correlation?.correlationId ?? null,
            service: 'federation',
            requestId: request.id,
            diagnostic: {
              endpoint: '/fetch',
              sub
            }
          })
        );

        return reply.code(200).header('Content-Type', 'application/entity-statement+jwt').send(subordinateStatement);
      } catch (error) {
        request.log.error({ err: error }, 'Subordinate statement generation failed');
        return reply.code(500).send({ error: 'internal_server_error' });
      }
    }
  });
};

export default fetchRoute;
