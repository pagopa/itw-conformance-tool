import { toFastifyJsonSchema } from '@itw-conformance-tool/utils';

import { getErasureHandler, getErasureQuerystringSchema, getErasureResponseSchema } from '../handlers/get-erasure.js';

import type { FastifyPluginAsync } from 'fastify';

const erasureRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/erasure',
    method: 'GET',
    schema: {
      operationId: 'getErasure',
      summary: 'Accept an erasure request',
      description: 'Accepts a Wallet Instance erasure request for the selected Relying Party.',
      tags: ['Erasure'],
      querystring: toFastifyJsonSchema(getErasureQuerystringSchema),
      response: {
        202: {
          description: 'The erasure request was accepted for later processing.',
          ...toFastifyJsonSchema(getErasureResponseSchema)
        }
      }
    },
    handler: getErasureHandler
  });
};

export default erasureRoute;
