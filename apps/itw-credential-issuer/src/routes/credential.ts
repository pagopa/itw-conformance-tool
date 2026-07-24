import { createHash } from 'node:crypto';

import { createObservedEvent } from '@itw-conformance-tool/conformance';

import { CreateCredentialError, CredentialService, InvalidProofError } from '../domain/index.js';
import { makeJwksRepository, makeOauthCallbacks } from '../plugins/index.js';

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
        return reply.code(statusCode).send(result.sdkResult.credentialResponse ?? result.sdkResult);
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
