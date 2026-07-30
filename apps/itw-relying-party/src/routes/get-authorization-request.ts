import { toFastifyJsonSchema } from '@itw-conformance-tool/utils';

import {
  getAuthorizationRequestHandler,
  getAuthorizationRequestParamsSchema,
  getAuthorizationRequestResponseSchema
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
};

export default getAuthorizationRequestRoute;
