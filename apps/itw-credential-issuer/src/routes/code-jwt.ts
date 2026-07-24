import { createHash } from 'node:crypto';

import { createObservedEvent } from '@itw-conformance-tool/conformance';

import { CodeJwtService, InvalidRequestUriError, formatSpecVersionHeader } from '../domain/index.js';
import { makeCodeJwtParRepository, makeJwksRepository, makeOauthCallbacks } from '../plugins/index.js';

import type { FastifyPluginAsync } from 'fastify';

function sha256HashArtifact(value: string): string {
  return `sha256:${createHash('sha256').update(value, 'utf8').digest('base64url')}`;
}

const codeJwtRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/code/jwt',
    method: 'GET',
    schema: {
      tags: ['Authorization'],
      querystring: {
        type: 'object',
        required: ['request_uri'],
        properties: {
          request_uri: { type: 'string' }
        }
      }
    },
    handler: async (request, reply) => {
      const requestUri = (request.query as { request_uri: string }).request_uri;
      const { baseURL, sdkConfig } = makeOauthCallbacks(app, request);
      const activeFault = app.issuerFaultStore.getActive();
      const missingClaimProfile =
        activeFault?.profile.type === 'authorization-response-missing-claim' ? activeFault.profile : undefined;

      try {
        const service = new CodeJwtService({
          baseURL,
          jwksRepository: makeJwksRepository(app),
          parRepository: makeCodeJwtParRepository(app)
        });

        const result = await service.createAuthorizationCodeJwt(requestUri, missingClaimProfile?.claim);

        if (missingClaimProfile && activeFault) {
          // Emission failures must not be reported as a successfully applied
          // fault: any error here surfaces through the outer catch below (as
          // a 500), rather than emitting a false "applied" event.
          await app.conformanceEventSink?.emit(
            createObservedEvent({
              name: 'issuer.fault.applied',
              correlationId: request.conformance?.correlation?.correlationId ?? null,
              service: 'credential-issuer',
              requestId: request.id,
              diagnostic: {
                endpoint: '/code/jwt',
                faultProfileType: missingClaimProfile.type,
                omittedClaim: missingClaimProfile.claim,
                scenarioId: activeFault.scenarioId,
                resolvedSpecVersion: formatSpecVersionHeader(sdkConfig.itWalletSpecsVersion),
                artifactHash: sha256HashArtifact(result.jwt),
                outcome: 'applied'
              }
            })
          );
        }

        return reply.code(200).header('Content-Type', 'text/html').send(result.formPost);
      } catch (error) {
        if (error instanceof InvalidRequestUriError) {
          return reply.code(400).send({ error: 'invalid_request', error_description: error.message });
        }

        request.log.error({ err: error }, 'Authorization code JWT generation failed');
        return reply.code(500).send({ error: 'internal_server_error' });
      }
    }
  });
};

export default codeJwtRoute;
