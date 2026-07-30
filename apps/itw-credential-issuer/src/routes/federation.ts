import { createObservedEvent } from '@itw-conformance-tool/conformance';
import { sha256HashArtifact } from '@itw-conformance-tool/utils';

import { FederationService, formatSpecVersionHeader } from '../domain/index.js';
import { makeJwksRepository, makeOauthCallbacks } from '../plugins/index.js';

import type { FastifyPluginAsync } from 'fastify';

/**
 * A syntactically valid, deterministic Entity ID that is never a real
 * federation participant: `.invalid` is reserved by RFC 2606 and guaranteed
 * to never resolve, so it can never accidentally form part of the wallet's
 * expected trust chain. Used only by the `invalid-trust-anchor` issuer
 * fault to replace `authority_hints`.
 */
const INVALID_TRUST_ANCHOR_ENTITY_ID = 'https://wp-046a-invalid-trust-anchor.itw-conformance-tool.invalid';

const federationRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/.well-known/openid-federation',
    method: 'GET',
    schema: {
      tags: ['Federation']
    },
    handler: async (request, reply) => {
      const { baseURL, sdkConfig } = makeOauthCallbacks(app, request);
      const activeFault = app.issuerFaultStore.getActive();
      const invalidTrustAnchorFault = activeFault?.profile.type === 'invalid-trust-anchor' ? activeFault : undefined;

      try {
        const service = new FederationService(makeJwksRepository(app));
        const statement = await service.getEntityConfiguration(
          baseURL,
          sdkConfig,
          app.config.TRUST_ANCHOR_ENTITY_ID,
          invalidTrustAnchorFault ? [INVALID_TRUST_ANCHOR_ENTITY_ID] : undefined
        );

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

        if (invalidTrustAnchorFault) {
          // Emission failures must not be reported as a successfully applied
          // fault: any error here surfaces through the outer catch below
          // (as a 500), rather than emitting a false "applied" event.
          await app.conformanceEventSink?.emit(
            createObservedEvent({
              name: 'issuer.fault.applied',
              correlationId: request.conformance?.correlation?.correlationId ?? null,
              service: 'credential-issuer',
              requestId: request.id,
              diagnostic: {
                endpoint: '/.well-known/openid-federation',
                faultProfileType: invalidTrustAnchorFault.profile.type,
                scenarioId: invalidTrustAnchorFault.scenarioId,
                resolvedSpecVersion: formatSpecVersionHeader(sdkConfig.itWalletSpecsVersion),
                artifactHash: sha256HashArtifact(statement),
                outcome: 'applied'
              }
            })
          );
        }

        return reply.code(200).header('Content-Type', 'application/entity-statement+jwt').send(statement);
      } catch (error) {
        request.log.error({ err: error }, 'OpenID federation metadata generation failed');
        return reply.code(500).send({ error: 'internal_server_error' });
      }
    }
  });
};

export default federationRoute;
