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
  type DigitalCredentialSignatureFaultProfile,
  type DigitalCredentialTrustChainFaultProfile,
  type MdocSignatureFaultProfile
} from '../domain/index.js';
import { STATUS_LIST_TESTED_CREDENTIAL_INDEX, STATUS_LIST_URI } from '../domain/models/status-list.js';
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/**
 * Hashes the `notification_id` from a *final* (post-fault) Credential
 * Response body, so `issuer.credential.issued` evidence can prove
 * correlation with the Notification Request (WP_064a) without ever storing
 * the raw value.
 */
function notificationIdSha256FromResponse(value: Record<string, unknown>): string | undefined {
  const notificationId = value.notification_id;
  return typeof notificationId === 'string' && notificationId.length > 0 ? sha256Base64Url(notificationId) : undefined;
}

function countResponseCredentials(value: Record<string, unknown>): number | undefined {
  return Array.isArray(value.credentials) ? value.credentials.length : undefined;
}

function countProofJwts(requestBody: unknown): number | undefined {
  const body = typeof requestBody === 'string' ? credentialRequestDiagnosticBody(requestBody) : requestBody;
  if (!isRecord(body) || !isRecord(body.proofs) || !Array.isArray(body.proofs.jwt)) {
    return undefined;
  }

  return body.proofs.jwt.length;
}

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

/** Narrows an active issuer fault to the WP_062a Digital Credential signature profile. */
function isDigitalCredentialSignatureFault(
  fault: ActiveIssuerFault | undefined
): fault is ActiveIssuerFault & { profile: DigitalCredentialSignatureFaultProfile } {
  return fault?.profile.type === 'edc-invalid-signature';
}

/** Narrows an active issuer fault to the WP_062b mdoc-CBOR signature profile. */
function isMdocSignatureFault(
  fault: ActiveIssuerFault | undefined
): fault is ActiveIssuerFault & { profile: MdocSignatureFaultProfile } {
  return fault?.profile.type === 'mdl-invalid-signature';
}

const credentialConfigurationIdFromRequest = (requestBody: unknown): string | undefined => {
  if (typeof requestBody === 'string') {
    try {
      return credentialConfigurationIdFromRequest(JSON.parse(requestBody) as unknown);
    } catch {
      return undefined;
    }
  }

  if (requestBody === null || typeof requestBody !== 'object') return undefined;
  const credentialIdentifier = (requestBody as { credential_identifier?: unknown }).credential_identifier;
  return typeof credentialIdentifier === 'string' && credentialIdentifier.length > 0 ? credentialIdentifier : undefined;
};

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
      const digitalCredentialSignatureFault = isDigitalCredentialSignatureFault(activeFault) ? activeFault : undefined;
      const mdocSignatureFault = isMdocSignatureFault(activeFault) ? activeFault : undefined;
      // The issuer fault store only ever activates a single fault at a time,
      // so at most one of these Digital Credential faults can be set.
      const disabilityCardFault =
        digitalCredentialClaimsFault ?? digitalCredentialTrustChainFault ?? digitalCredentialSignatureFault;

      reply.header('Cache-Control', 'no-store');

      try {
        const service = new CredentialService(
          makeJwksRepository(app),
          app.nonceRepository,
          app.deferredCredentialRepository
        );
        const result = await service.createCredential({
          baseURL,
          batchIssuanceByDeferred: app.issuerRuntimeConfigStore.resolveBatchIssuanceByDeferred(
            app.config.BATCH_ISSUANCE_BY_DEFERRED
          ),
          body,
          callbacks: {
            hash: oauthCallbacks.hash,
            verifyJwt: oauthCallbacks.verifyJwt
          },
          config: sdkConfig,
          disabilityCardFaultProfile: disabilityCardFault?.profile,
          headers,
          method: request.method as HttpMethod,
          mdocFaultProfile: mdocSignatureFault?.profile,
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

        if (mdocSignatureFault && result.mdocFaultEvidence) {
          await app.conformanceEventSink?.emit(
            createObservedEvent({
              name: 'issuer.fault.applied',
              correlationId: request.conformance?.correlation?.correlationId ?? null,
              service: 'credential-issuer',
              requestId: request.id,
              diagnostic: {
                endpoint: '/credential',
                faultProfileType: mdocSignatureFault.profile.type,
                scenarioId: mdocSignatureFault.scenarioId,
                resolvedSpecVersion: formatSpecVersionHeader(sdkConfig.itWalletSpecsVersion),
                ...result.mdocFaultEvidence,
                credentialConfigurationId: credentialConfigurationIdFromRequest(request.body),
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

        if (result.status === 'deferred' && isRecord(responseBody)) {
          const transactionId = responseBody.transaction_id;
          const interval = responseBody.interval;
          const proofCount = countProofJwts(request.body);

          await app.conformanceEventSink?.emit(
            createObservedEvent({
              name: 'issuer.credential.deferred',
              correlationId: request.conformance?.correlation?.correlationId ?? null,
              service: 'credential-issuer',
              requestId: request.id,
              diagnostic: {
                endpoint: '/credential',
                statusCode,
                contentType: 'application/json',
                responseKind: 'deferred',
                intervalSeconds: typeof interval === 'number' ? interval : undefined,
                transactionIdSha256: typeof transactionId === 'string' ? sha256Base64Url(transactionId) : undefined,
                proofCount,
                credentialCount: proofCount,
                credentialsPresent: Object.hasOwn(responseBody, 'credentials')
              }
            })
          );
        }

        if (result.status === 'immediate' && isRecord(responseBody)) {
          await app.conformanceEventSink?.emit(
            createObservedEvent({
              name: 'issuer.credential.issued',
              correlationId: request.conformance?.correlation?.correlationId ?? null,
              service: 'credential-issuer',
              requestId: request.id,
              diagnostic: {
                endpoint: '/credential',
                statusCode,
                contentType: 'application/json',
                responseKind: 'immediate',
                responseHash: sha256Base64Url(JSON.stringify(responseBody)),
                statusListIndex: STATUS_LIST_TESTED_CREDENTIAL_INDEX,
                statusListUri: STATUS_LIST_URI(baseURL),
                credentialCount: countResponseCredentials(responseBody),
                notificationIdSha256: notificationIdSha256FromResponse(responseBody)
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
