import { toFastifyJsonSchema } from '@itw-conformance-tool/utils';

import { getStatusHandler, getStatusParamsSchema, getStatusResponseSchema } from '../handlers/get-status.js';

import type { FastifyPluginAsync } from 'fastify';

const getStatusRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/status/:state',
    method: 'GET',
    schema: {
      operationId: 'getAuthorizationStatus',
      summary: 'Poll the wallet session status',
      description:
        'Returns the current relying-party redirect target for the provided authorization state. ' +
        'Answered only for the browser that created the authorization request, which is identified by ' +
        'the session cookie it was issued; any other caller receives 404.',
      tags: ['Status'],
      params: toFastifyJsonSchema(getStatusParamsSchema),
      response: {
        200: {
          description: 'Current redirect target and optional verified credential values.',
          ...toFastifyJsonSchema(getStatusResponseSchema)
        }
      }
    },
    handler: getStatusHandler
  });
};

export default getStatusRoute;
