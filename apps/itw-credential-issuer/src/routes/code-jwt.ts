import { createHash } from 'node:crypto';

import { createObservedEvent } from '@itw-conformance-tool/conformance';

import { CodeJwtService, InvalidRequestUriError, formatSpecVersionHeader } from '../domain/index.js';
import { makeCodeJwtParRepository, makeJwksRepository, makeOauthCallbacks } from '../plugins/index.js';

import type { FastifyPluginAsync } from 'fastify';

type AuthorizationResponseFaultProfile =
  | { readonly type: 'authorization-response-missing-claim'; readonly claim: 'code' | 'iss' | 'state' }
  | { readonly type: 'authorization-response-invalid-state' };

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
      const authorizationResponseFault = [
        'authorization-response-missing-claim',
        'authorization-response-invalid-state'
      ].includes(activeFault?.profile.type ?? '')
        ? (activeFault?.profile as AuthorizationResponseFaultProfile)
        : undefined;

      try {
        const service = new CodeJwtService({
          baseURL,
          jwksRepository: makeJwksRepository(app),
          parRepository: makeCodeJwtParRepository(app)
        });

        const mutation =
          authorizationResponseFault?.type === 'authorization-response-missing-claim'
            ? { type: 'omit-claim' as const, claim: authorizationResponseFault.claim }
            : authorizationResponseFault?.type === 'authorization-response-invalid-state'
              ? { type: 'replace-state' as const }
              : undefined;

        const result = await service.createAuthorizationCodeJwt(requestUri, mutation);

        if (authorizationResponseFault && activeFault) {
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
                faultProfileType: authorizationResponseFault.type,
                ...(authorizationResponseFault.type === 'authorization-response-missing-claim'
                  ? { omittedClaim: authorizationResponseFault.claim }
                  : { mutatedClaim: 'state' }),
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
