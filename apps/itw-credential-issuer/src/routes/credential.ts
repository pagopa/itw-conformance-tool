import { createHash } from 'node:crypto';

import { createObservedEvent } from '@itw-conformance-tool/conformance';
import { sha256HashArtifact } from '@itw-conformance-tool/utils';

import {
  applyCredentialResponseFault,
  CreateCredentialError,
  CredentialService,
  formatSpecVersionHeader,
  InvalidProofError,
  type ActiveIssuerFault,
  type CredentialResponseFaultProfile,
  type DigitalCredentialClaimsFaultProfile,
  type DigitalCredentialTrustChainFaultProfile
} from '../domain/index.js';
import { makeJwksRepository, makeOauthCallbacks } from '../plugins/index.js';

import type { CredentialResponse } from '@pagopa/io-wallet-oid4vci';
import type { HttpMethod } from '@pagopa/io-wallet-utils';
import type { FastifyPluginAsync } from 'fastify';

const sha256Base64Url = (value: string): string => createHash('sha256').update(value, 'ascii').digest('base64url');

const firstHeaderValue = (value: string | string[] | undefined): string | undefined =>
  Array.isArray(value) ? value.at(0) : value;

const parseAuthorizationHeader = (authorizationHeader: string | undefined) => {
  const [scheme, token] = authorizationHeader?.match(/^(\S+)\s+(.+)$/)?.slice(1) ?? [];
  return { scheme, token };
};

const credentialRequestDiagnosticBody = (requestBody: unknown): unknown => {
  if (typeof requestBody !== 'string') {
    return requestBody ?? {};
  }

  return JSON.parse(requestBody) as unknown;
};

/** Narrows an active issuer fault to the Credential Response profile, so its `parameters` field is accessible. */
function isCredentialResponseFault(
  fault: ActiveIssuerFault | undefined
): fault is ActiveIssuerFault & { profile: CredentialResponseFaultProfile } {
  return fault?.profile.type === 'edc-missing-required-claims';
}

/** Narrows an active issuer fault to the WP_060 Digital Credential claims profile, so its `variant` field is accessible. */
function isDigitalCredentialClaimsFault(
  fault: ActiveIssuerFault | undefined
): fault is ActiveIssuerFault & { profile: DigitalCredentialClaimsFaultProfile } {
  return fault?.profile.type === 'digital-credential-claims-invalid';
}

/** Narrows an active issuer fault to the WP_061 Digital Credential trust-chain profile. */
function isDigitalCredentialTrustChainFault(
  fault: ActiveIssuerFault | undefined
): fault is ActiveIssuerFault & { profile: DigitalCredentialTrustChainFaultProfile } {
  return fault?.profile.type === 'edc-invalid-trust-chain';
}

const credentialRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/credential',
    method: 'POST',
    schema: {
      tags: ['Credential']
    },
    handler: async (request, reply) => {
      const body = typeof request.body === 'string' ? request.body : JSON.stringify(request.body ?? {});
      const { baseURL, headers, oauthCallbacks, sdkConfig } = makeOauthCallbacks(app, request);
      const { scheme: authorizationScheme, token: accessToken } = parseAuthorizationHeader(
        firstHeaderValue(request.headers.authorization)
      );
      const dpopProof = firstHeaderValue(request.headers.dpop);
      const activeFault = app.issuerFaultStore.getActive();
      const credentialResponseFault = isCredentialResponseFault(activeFault) ? activeFault : undefined;
      const digitalCredentialClaimsFault = isDigitalCredentialClaimsFault(activeFault) ? activeFault : undefined;
      const digitalCredentialTrustChainFault = isDigitalCredentialTrustChainFault(activeFault)
        ? activeFault
        : undefined;
      // The issuer fault store only ever activates a single fault at a time,
      // so at most one of these two can be set.
      const disabilityCardFault = digitalCredentialClaimsFault ?? digitalCredentialTrustChainFault;

      reply.header('Cache-Control', 'no-store');

      try {
        const service = new CredentialService(
          makeJwksRepository(app),
          app.nonceRepository,
          app.deferredCredentialRepository
        );
        const result = await service.createCredential({
          baseURL,
          batchIssuanceByDeferred: app.config.BATCH_ISSUANCE_BY_DEFERRED,
          body,
          callbacks: {
            hash: oauthCallbacks.hash,
            verifyJwt: oauthCallbacks.verifyJwt
          },
          config: sdkConfig,
          disabilityCardFaultProfile: disabilityCardFault?.profile,
          headers,
          method: request.method as HttpMethod,
          trustedWalletProviderIssuers: app.config.TRUSTED_WALLET_PROVIDER_ISSUERS,
          url: `${baseURL}${request.url}`
        });

        await app.conformanceEventSink?.emit(
          createObservedEvent({
            name: 'issuer.credential.requested',
            correlationId: request.conformance?.correlation?.correlationId ?? null,
            service: 'credential-issuer',
            requestId: request.id,
            diagnostic: {
              endpoint: '/credential',
              method: 'POST',
              contentType: firstHeaderValue(request.headers['content-type']),
              authorizationScheme,
              accessTokenSha256: accessToken ? sha256Base64Url(accessToken) : undefined,
              dpopProof,
              body: credentialRequestDiagnosticBody(request.body)
            }
          })
        );

        const statusCode = result.status === 'deferred' ? 202 : 200;
        let responseBody: unknown = result.sdkResult.credentialResponse ?? result.sdkResult;

        if (disabilityCardFault && result.disabilityCardFaultEvidence) {
          await app.conformanceEventSink?.emit(
            createObservedEvent({
              name: 'issuer.fault.applied',
              correlationId: request.conformance?.correlation?.correlationId ?? null,
              service: 'credential-issuer',
              requestId: request.id,
              diagnostic: {
                endpoint: '/credential',
                faultProfileType: disabilityCardFault.profile.type,
                scenarioId: disabilityCardFault.scenarioId,
                resolvedSpecVersion: formatSpecVersionHeader(sdkConfig.itWalletSpecsVersion),
                ...result.disabilityCardFaultEvidence,
                artifactHash: sha256HashArtifact(JSON.stringify(responseBody)),
                statusCode,
                contentType: 'application/json',
                outcome: 'applied'
              }
            })
          );
        }

        if (credentialResponseFault && result.status === 'immediate') {
          const mutation = applyCredentialResponseFault({
            profile: credentialResponseFault.profile,
            response: responseBody as CredentialResponse,
            responseKind: result.status
          });

          if (!mutation.ok) {
            request.log.error(
              { reason: mutation.reason },
              'Credential Response fault could not be applied; failing closed'
            );
            return reply.code(500).send({ error: 'internal_server_error' });
          }

          responseBody = mutation.mutation.body;

          await app.conformanceEventSink?.emit(
            createObservedEvent({
              name: 'issuer.fault.applied',
              correlationId: request.conformance?.correlation?.correlationId ?? null,
              service: 'credential-issuer',
              requestId: request.id,
              diagnostic: {
                endpoint: '/credential',
                faultProfileType: credentialResponseFault.profile.type,
                scenarioId: credentialResponseFault.scenarioId,
                resolvedSpecVersion: formatSpecVersionHeader(sdkConfig.itWalletSpecsVersion),
                omittedParameters: mutation.mutation.omittedParameters,
                artifactHash: sha256HashArtifact(JSON.stringify(responseBody)),
                statusCode,
                contentType: 'application/json',
                outcome: 'applied'
              }
            })
          );
        }

        return reply.code(statusCode).send(responseBody);
      } catch (error) {
        if (error instanceof InvalidProofError) {
          return reply.code(400).send({ error: 'invalid_or_missing_proof', error_description: error.message });
        }

        if (error instanceof CreateCredentialError) {
          return reply.code(400).send({ error: 'invalid_request', error_description: error.message });
        }

        request.log.error({ err: error }, 'Credential issuance failed');
        return reply.code(500).send({ error: 'internal_server_error' });
      }
    }
  });
};

export default credentialRoute;
