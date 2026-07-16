import {
  authorizationResponsePayloadSchema,
  authorizationResponseResultSchema,
  getAuthorizationResponseHandler,
  sessionIdQuerystringSchema
} from '../handlers/get-authorization-response.js';
import { toFastifyJsonSchema } from '../utils/json-schema.js';

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
          description: 'Absolute redirect URI used to continue the relying-party flow.',
          ...toFastifyJsonSchema(authorizationResponseResultSchema)
        }
      }
    },
    handler: getAuthorizationResponseHandler
  });
};

export default authorizationResponseRoute;
