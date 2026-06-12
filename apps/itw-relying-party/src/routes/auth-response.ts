import { registerAuthResponseConformanceHooks } from '../hooks/conformance.js';
import { verifyAuthorizationResponseUseCase } from '../use-cases/verify-authorization-response.js';

import type { FastifyPluginAsync } from 'fastify';

const OAUTH_ERROR_VALUES = new Set([
  'invalid_request_object',
  'invalid_request_uri',
  'vp_formats_not_supported',
  'invalid_request',
  'access_denied',
  'invalid_client'
]);

class InvalidAuthorizationResponseBodyError extends Error {
  readonly statusCode = 400;

  constructor() {
    super('The request is missing required parameters');
    this.name = 'InvalidAuthorizationResponseBodyError';
  }
}

function parseAuthResponseBody(
  body: unknown
): { kind: 'oauth-error'; state: string } | { kind: 'jarm'; response: string } {
  if (!body || typeof body !== 'object') {
    throw new InvalidAuthorizationResponseBodyError();
  }

  const payload = body as Record<string, unknown>;
  const response = payload.response;
  const error = payload.error;
  const state = payload.state;

  const isJarm = typeof response === 'string' && error === undefined && state === undefined;
  if (isJarm) {
    return { kind: 'jarm', response };
  }

  const isOauthError =
    response === undefined && typeof error === 'string' && OAUTH_ERROR_VALUES.has(error) && typeof state === 'string';
  if (isOauthError) {
    return { kind: 'oauth-error', state };
  }

  throw new InvalidAuthorizationResponseBodyError();
}

const authResponseRoute: FastifyPluginAsync = async (app) => {
  registerAuthResponseConformanceHooks(app);

  app.route({
    url: '/auth/response',
    method: 'POST',
    schema: {
      tags: ['Relying Party']
    },
    handler: async (request, reply) => {
      const parsedBody = parseAuthResponseBody(request.body);

      if (parsedBody.kind === 'oauth-error') {
        try {
          await app.sessionService.update(parsedBody.state, 'rejected');
        } catch {
          // Ignore unknown sessions for OAuth error callbacks.
        }
        return reply.code(200).send({});
      }

      const result = await verifyAuthorizationResponseUseCase({
        baseUrl: app.config.baseUrl,
        jarmResponse: parsedBody.response,
        nonceRepository: app.nonceRepository,
        privateKeyPem: app.rpKeys.authResponsePrivateKeyPem,
        sessionService: app.sessionService,
        trustChain: app.trustChain as [string, ...string[]] // The trustChain plugin guarantees this type
      });

      return reply.code(200).send({ redirect_uri: result.redirectUri });
    }
  });
};

export default authResponseRoute;
