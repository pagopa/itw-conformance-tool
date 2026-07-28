import { toFastifyJsonSchema } from '@itw-conformance-tool/utils';

import { getCallbackHandler, getCallbackParamsSchema, getCallbackQuerystringSchema } from '../handlers/get-callback.js';

import type { FastifyPluginAsync } from 'fastify';

const callbackRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/callback/:state',
    method: 'GET',
    schema: {
      operationId: 'getPresentationCallback',
      summary: 'Relying Party redirect callback',
      description: 'Landing endpoint the wallet redirects the user-agent to after a completed presentation.',
      tags: ['Authorization'],
      params: toFastifyJsonSchema(getCallbackParamsSchema),
      querystring: toFastifyJsonSchema(getCallbackQuerystringSchema)
    },
    handler: getCallbackHandler
  });
};

export default callbackRoute;
