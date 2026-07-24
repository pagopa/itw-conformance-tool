import { toFastifyJsonSchema } from '@itw-conformance-tool/utils';

import { getHealthCheckHandler, healthCheckResponseSchema } from '../handlers/health.js';

import type { FastifyPluginAsync } from 'fastify';

const healthRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/health',
    method: 'GET',
    schema: {
      tags: ['Health'],
      response: {
        200: {
          description: 'Service is alive.',
          ...toFastifyJsonSchema(healthCheckResponseSchema)
        }
      }
    },
    handler: getHealthCheckHandler
  });
};

export default healthRoute;
