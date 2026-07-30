import { toFastifyJsonSchema } from '@itw-conformance-tool/utils';

import {
  getAuthorizationRequestHandler,
  getAuthorizationRequestParamsSchema,
  getAuthorizationRequestResponseSchema,
  postAuthorizationRequestBodySchema
} from '../handlers/get-authorization-request.js';

import type { FastifyPluginAsync } from 'fastify';

const getAuthorizationRequestRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/auth/request/:state',
    method: 'GET',
    schema: {
      operationId: 'getAuthorizationRequest',
      summary: 'Fetch the signed authorization request',
      description: 'Returns the signed request object JWT referenced by the wallet request_uri.',
      tags: ['Authorization'],
      params: toFastifyJsonSchema(getAuthorizationRequestParamsSchema),
      produces: ['application/oauth-authz-req+jwt'],
      response: {
        200: {
          description: 'Signed authorization request JWT.',
          ...toFastifyJsonSchema(getAuthorizationRequestResponseSchema)
        }
      }
    },
    handler: getAuthorizationRequestHandler
  });

  // request_uri_method=post: the wallet sends its metadata and a fresh nonce in
  // an application/x-www-form-urlencoded body, and the Request Object it gets
  // back echoes that nonce.
  app.route({
    url: '/auth/request/:state',
    method: 'POST',
    schema: {
      operationId: 'postAuthorizationRequest',
      summary: 'Fetch the signed authorization request with wallet metadata',
      description:
        'Returns the signed request object JWT referenced by the wallet request_uri, echoing the supplied wallet_nonce.',
      tags: ['Authorization'],
      params: toFastifyJsonSchema(getAuthorizationRequestParamsSchema),
      body: toFastifyJsonSchema(postAuthorizationRequestBodySchema),
      consumes: ['application/x-www-form-urlencoded'],
      produces: ['application/oauth-authz-req+jwt'],
      response: {
        200: {
          description: 'Signed authorization request JWT.',
          ...toFastifyJsonSchema(getAuthorizationRequestResponseSchema)
        }
      }
    },
    handler: getAuthorizationRequestHandler
  });
};

export default getAuthorizationRequestRoute;
