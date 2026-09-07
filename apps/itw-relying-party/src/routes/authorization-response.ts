import { toFastifyJsonSchema } from '@itw-conformance-tool/utils';

import {
  authorizationResponseErrorSchema,
  authorizationResponsePayloadSchema,
  authorizationResponseResultSchema,
  getAuthorizationResponseHandler,
  sessionIdQuerystringSchema
} from '../handlers/get-authorization-response.js';

import type { FastifyPluginAsync } from 'fastify';

const authorizationResponseRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/auth/response',
    method: 'POST',
    schema: {
      operationId: 'handleAuthorizationResponse',
      summary: 'Process the wallet authorization response',
      description: 'Accepts the direct_post.jwt callback from the wallet and returns the next browser redirect URI.',
      tags: ['Authorization'],
      body: toFastifyJsonSchema(authorizationResponsePayloadSchema),
      consumes: ['application/x-www-form-urlencoded'],
      querystring: toFastifyJsonSchema(sessionIdQuerystringSchema),
      response: {
        200: {
          description:
            'Acknowledgement. Carries the redirect URI used to continue the relying-party flow in the same-device flow; an empty object for cross-device and for an authorization error response.',
          ...toFastifyJsonSchema(authorizationResponseResultSchema)
        },
        400: {
          description: 'The authorization response could not be parsed or decrypted.',
          ...toFastifyJsonSchema(authorizationResponseErrorSchema)
        },
        403: {
          description: 'The vp_token was parsed but failed verification.',
          ...toFastifyJsonSchema(authorizationResponseErrorSchema)
        }
      }
    },
    handler: getAuthorizationResponseHandler
  });
};

export default authorizationResponseRoute;
