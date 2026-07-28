import { toFastifyJsonSchema } from '@itw-conformance-tool/utils';

import { getCallbackHandler, getCallbackQuerystringSchema } from '../handlers/get-callback.js';

import type { FastifyPluginAsync } from 'fastify';

const callbackRoute: FastifyPluginAsync = async (app) => {
  // The path carries no session identifier: it must stay byte-for-byte the
  // `redirect_uris` entry the Entity Configuration attests, so only the query
  // string varies between sessions (see `getCallbackQuerystringSchema`).
  app.route({
    url: '/callback',
    method: 'GET',
    schema: {
      operationId: 'getPresentationCallback',
      summary: 'Relying Party redirect callback',
      description: 'Landing endpoint the wallet redirects the user-agent to after a completed presentation.',
      tags: ['Authorization'],
      querystring: toFastifyJsonSchema(getCallbackQuerystringSchema)
    },
    handler: getCallbackHandler
  });
};

export default callbackRoute;
