import { createHash } from 'node:crypto';

import { createObservedEvent } from '@itw-conformance-tool/conformance';
import { isInternalServiceRequest } from '@itw-conformance-tool/utils';

import { createTrustAnchorEntityConfiguration } from '../federation/statements.js';

import type { FastifyPluginAsync } from 'fastify';

function sha256HashJwt(jwt: string): string {
  return `sha256:${createHash('sha256').update(jwt, 'utf8').digest('base64url')}`;
}

const federationRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/.well-known/openid-federation',
    method: 'GET',
    schema: {
      tags: ['Federation']
    },
    handler: async (request, reply) => {
      try {
        const activeFault = app.trustAnchorFaultStore.getActive();
        const useFaultKey = activeFault?.profile.type === 'entity-configuration-nonmatching-signing-key';
        const federationPrivateJwk = useFaultKey
          ? app.trustAnchorFaultKeys.entityConfigurationNonmatchingSigningPrivateJwk
          : app.trustAnchorKeys.federationPrivateJwk;
        const entityConfiguration = await createTrustAnchorEntityConfiguration({
          federationPrivateJwk,
          issuerEntityId: app.config.issuerEntityId,
          relyingPartyEntityId: app.config.rpEntityId,
          trustAnchorBaseUrl: app.config.baseUrl
        });

        // Trust Chain resolution step: the wallet fetches the Trust Anchor
        // Entity Configuration (WP_079). The request carries no scenario
        // correlation, so it is adopted as uncorrelated evidence narrowed by the
        // endpoint diagnostic.
        //
        // A call from another conformance-tool service — the Relying Party
        // assembling an inlined Trust Chain — is not the wallet resolving
        // anything, so it produces no evidence, neither of the resolution step
        // nor of the fault it was served.
        const isWalletObservation = !isInternalServiceRequest(request.headers);

        if (isWalletObservation) {
          await app.conformanceEventSink?.emit(
            createObservedEvent({
              name: 'trust_anchor.entity_configuration.requested',
              correlationId: request.conformance?.correlation?.correlationId ?? null,
              service: 'federation',
              requestId: request.id,
              diagnostic: { endpoint: '/.well-known/openid-federation' }
            })
          );
          await app.conformanceEventSink?.emit(
            createObservedEvent({
              name: 'federation.anchor.requested',
              correlationId: request.conformance?.correlation?.correlationId ?? null,
              service: 'federation',
              requestId: request.id,
              diagnostic: { endpoint: '/.well-known/openid-federation' }
            })
          );
        }

        if (isWalletObservation && useFaultKey && activeFault) {
          await app.conformanceEventSink?.emit(
            createObservedEvent({
              name: 'trust_anchor.fault.applied',
              correlationId: request.conformance?.correlation?.correlationId ?? null,
              service: 'federation',
              requestId: request.id,
              diagnostic: {
                artifactHash: sha256HashJwt(entityConfiguration),
                endpoint: '/.well-known/openid-federation',
                faultProfileType: activeFault.profile.type,
                outcome: 'applied',
                scenarioId: activeFault.scenarioId,
                specVersion: activeFault.specVersion
              }
            })
          );
        }

        return reply.code(200).header('Content-Type', 'application/entity-statement+jwt').send(entityConfiguration);
      } catch (error) {
        request.log.error({ err: error }, 'Trust Anchor entity configuration generation failed');
        return reply.code(500).send({ error: 'internal_server_error' });
      }
    }
  });
};

export default federationRoute;
