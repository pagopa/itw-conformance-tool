import {
  createAuthorizationRequestHandler,
  createAuthorizationRequestPayloadSchema,
  createAuthorizationRequestResponseSchema
} from '../handlers/create-authorization-request.js';
import { toFastifyJsonSchema } from '../utils/json-schema.js';

import type { FastifyPluginAsync } from 'fastify';

export const authorizationRequestRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/create-authorization-request',
    method: 'POST',
    schema: {
      operationId: 'createAuthorizationRequest',
      summary: 'Create a wallet authorization request',
      description:
        'Builds a signed request object, stores the relying-party session, and returns the wallet launch URL.',
      tags: ['Authorization'],
      body: toFastifyJsonSchema(createAuthorizationRequestPayloadSchema),
      response: {
        200: {
          description: 'Wallet launch URL built from the generated request object.',
          ...toFastifyJsonSchema(createAuthorizationRequestResponseSchema)
        }
      }
    },
    handler: createAuthorizationRequestHandler
  });
};

export default authorizationRequestRoute;
