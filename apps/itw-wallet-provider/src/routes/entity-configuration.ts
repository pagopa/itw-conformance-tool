import { toFastifyJsonSchema } from '@itw-conformance-tool/utils';

import {
  createEntityConfigurationHandler,
  entityConfigurationResponseSchema
} from '../handlers/create-entity-configuration.js';

import type { FastifyPluginAsync } from 'fastify';

const federationRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/.well-known/openid-federation',
    method: 'GET',
    schema: {
      tags: ['Federation'],
      produces: ['application/entity-statement+jwt'],
      response: {
        200: {
          description: 'Signed OpenID Federation entity statement JWT.',
          ...toFastifyJsonSchema(entityConfigurationResponseSchema)
        }
      }
    },
    handler: createEntityConfigurationHandler
  });
};

export default federationRoute;
