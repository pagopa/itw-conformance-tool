import { createHash } from 'node:crypto';

import { createObservedEvent } from '@itw-conformance-tool/conformance';
import { Oauth2Error } from '@pagopa/io-wallet-oauth2';

import {
  CreateAccessTokenError,
  InvalidClientError,
  InvalidDpopProofError,
  InvalidGrantError,
  TokenService,
  UnsupportedGrantTypeError
} from '../domain/index.js';
import { ACCESS_TOKEN_TTL_SECONDS, REFRESH_TOKEN_TTL_SECONDS } from '../domain/models/token.js';
import {
  makeJwksRepository,
  makeOauthCallbacks,
  makeRefreshTokenRepository,
  makeTokenParRepository
} from '../plugins/index.js';

import type { HttpMethod } from '@pagopa/io-wallet-utils';
import type { FastifyPluginAsync, FastifyReply } from 'fastify';

const tokenRoute: FastifyPluginAsync = async (app) => {
  const noCacheHeaders = {
    'Cache-Control': 'no-store',
    Pragma: 'no-cache'
  };
  const withNoCache = (reply: FastifyReply) => reply.headers(noCacheHeaders);

  app.route({
    url: '/token',
    method: 'POST',
    schema: {
      tags: ['Authorization']
    },
    handler: async (request, reply) => {
      const bodyString =
        typeof request.body === 'string'
          ? request.body
          : new URLSearchParams(
              Object.entries((request.body ?? {}) as Record<string, string | number | boolean | null | undefined>)
                .filter(([, value]) => value !== undefined && value !== null)
                .map(([key, value]) => [key, String(value)] as [string, string])
            ).toString();
      const { baseURL, oauthCallbacks, sdkConfig } = makeOauthCallbacks(app, request);
      const form = new URLSearchParams(bodyString);
      const grantType = form.get('grant_type') ?? undefined;
      const presentedRefreshToken = form.get('refresh_token') ?? undefined;
      const scenarioCorrelationId = request.conformance?.correlation?.correlationId ?? null;
      const dpopHeaderPresent = request.headers.dpop !== undefined;

      const emitTokenFailure = async (input: { error: string; statusCode: number }): Promise<void> => {
        await app.conformanceEventSink?.emit(
          createObservedEvent({
            name: 'issuer.token.failed',
            correlationId: scenarioCorrelationId,
            service: 'credential-issuer',
            requestId: request.id,
            diagnostic: {
              endpoint: '/token',
              grantType,
              error: input.error,
              statusCode: input.statusCode,
              dpopHeaderPresent,
              requestId: request.id,
              scenarioCorrelationId
            }
          })
        );
      };

      try {
        const service = new TokenService(
          makeTokenParRepository(app),
          makeJwksRepository(app),
          makeRefreshTokenRepository(app),
          {
            accessTokenTtlSeconds: app.issuerRuntimeConfigStore.resolveAccessTokenTtlSeconds(ACCESS_TOKEN_TTL_SECONDS),
            refreshTokenTtlSeconds:
              app.issuerRuntimeConfigStore.resolveRefreshTokenTtlSeconds(REFRESH_TOKEN_TTL_SECONDS)
          }
        );
        const tokenRequestHeaders = new Headers(
          Object.entries(request.headers)
            .filter(([, value]) => typeof value === 'string' || Array.isArray(value))
            .map(([key, value]) => [key, Array.isArray(value) ? value.join(',') : value] as [string, string])
        );
        const { issuedAccessToken, issuedRefreshToken, issuerState, response } = await service.createAccessToken({
          baseURL,
          callbacks: {
            generateRandom: oauthCallbacks.generateRandom,
            hash: oauthCallbacks.hash,
            signJwt: oauthCallbacks.signJwt,
            verifyJwt: oauthCallbacks.verifyJwt
          },
          config: sdkConfig,
          tokenRequest: {
            bodyString,
            headers: tokenRequestHeaders,
            method: request.method as HttpMethod,
            url: `${baseURL}/token`
          }
        });

        await app.conformanceEventSink?.emit(
          createObservedEvent({
            name: 'issuer.token.requested',
            correlationId: issuerState ?? request.conformance?.correlation?.correlationId ?? null,
            service: 'credential-issuer',
            requestId: request.id,
            diagnostic: {
              endpoint: '/token',
              accessTokenExp: issuedAccessToken.exp,
              accessTokenExpiresIn: issuedAccessToken.expiresIn,
              accessTokenSha256: issuedAccessToken.sha256,
              body: request.body,
              grantType,
              headers: Object.fromEntries(tokenRequestHeaders.entries()),
              method: request.method,
              presentedRefreshTokenSha256: presentedRefreshToken ? sha256Base64Url(presentedRefreshToken) : undefined,
              refreshTokenExp: issuedRefreshToken?.exp,
              refreshTokenSha256: issuedRefreshToken?.sha256,
              tokenType: typeof response.token_type === 'string' ? response.token_type : undefined
            }
          })
        );

        return reply
          .code(200)
          .headers({ ...noCacheHeaders, 'Content-Type': 'application/json' })
          .send(response);
      } catch (error) {
        if (error instanceof CreateAccessTokenError) {
          await emitTokenFailure({ error: 'invalid_request', statusCode: 400 });
          return withNoCache(reply).code(400).send({ error: 'invalid_request', error_description: error.message });
        }

        if (error instanceof InvalidGrantError) {
          await emitTokenFailure({ error: 'invalid_grant', statusCode: 400 });
          return withNoCache(reply).code(400).send({ error: 'invalid_grant', error_description: error.message });
        }

        if (error instanceof UnsupportedGrantTypeError) {
          await emitTokenFailure({ error: 'unsupported_grant_type', statusCode: 400 });
          return withNoCache(reply)
            .code(400)
            .send({ error: 'unsupported_grant_type', error_description: error.message });
        }

        if (error instanceof InvalidDpopProofError) {
          await emitTokenFailure({ error: 'invalid_dpop_proof', statusCode: 400 });
          return withNoCache(reply).code(400).send({ error: 'invalid_dpop_proof', error_description: error.message });
        }

        if (error instanceof InvalidClientError) {
          await emitTokenFailure({ error: 'invalid_client', statusCode: 401 });
          return withNoCache(reply).code(401).send({ error: 'invalid_client', error_description: error.message });
        }

        if (error instanceof Oauth2Error) {
          await emitTokenFailure({ error: 'invalid_request', statusCode: 400 });
          return withNoCache(reply).code(400).send({
            error: 'invalid_request',
            error_description: error.message
          });
        }

        request.log.error({ err: error }, 'Token request failed');
        return withNoCache(reply).code(500).send({ error: 'internal_server_error' });
      }
    }
  });
};

export default tokenRoute;

function sha256Base64Url(value: string): string {
  return createHash('sha256').update(value, 'ascii').digest('base64url');
}
