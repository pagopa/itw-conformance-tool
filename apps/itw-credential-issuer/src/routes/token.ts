import { Oauth2Error } from '@pagopa/io-wallet-oauth2';

import { CreateAccessTokenError, InvalidGrantError, TokenService, UnsupportedGrantTypeError } from '../domain/index.js';
import { makeJwksRepository, makeOauthCallbacks, makeTokenParRepository } from '../plugins/index.js';

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

      try {
        const service = new TokenService(makeTokenParRepository(app), makeJwksRepository(app));
        const tokenRequestHeaders = new Headers(
          Object.entries(request.headers)
            .filter(([, value]) => typeof value === 'string' || Array.isArray(value))
            .map(([key, value]) => [key, Array.isArray(value) ? value.join(',') : value] as [string, string])
        );
        const response = await service.createAccessToken({
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

        return reply
          .code(200)
          .headers({ ...noCacheHeaders, 'Content-Type': 'application/json' })
          .send(response);
      } catch (error) {
        if (error instanceof CreateAccessTokenError) {
          return withNoCache(reply).code(400).send({ error: 'invalid_request', error_description: error.message });
        }

        if (error instanceof InvalidGrantError) {
          return withNoCache(reply).code(400).send({ error: 'invalid_grant', error_description: error.message });
        }

        if (error instanceof UnsupportedGrantTypeError) {
          return withNoCache(reply)
            .code(400)
            .send({ error: 'unsupported_grant_type', error_description: error.message });
        }

        if (error instanceof Oauth2Error) {
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
