import {
  createEntityConfigurationHandler,
  entityConfigurationResponseSchema
} from '../handlers/create-entity-configuration.js';
import { toFastifyJsonSchema } from '../utils/json-schema.js';

import type { FastifyPluginAsync } from 'fastify';

const entityConfigurationRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/.well-known/openid-federation',
    method: 'GET',
    schema: {
      operationId: 'getEntityConfiguration',
      summary: 'Fetch the OpenID Federation entity statement',
      description: 'Returns the signed entity configuration for the relying party as an entity-statement JWT.',
      tags: ['Entity Configuration'],
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

export default entityConfigurationRoute;
