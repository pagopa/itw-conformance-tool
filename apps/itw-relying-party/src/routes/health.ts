import { getHealthCheckHandler, healthCheckResponseSchema } from '../handlers/health.js';
import { toFastifyJsonSchema } from '../utils/json-schema.js';

import type { FastifyPluginAsync } from 'fastify';

const healthRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/health',
    method: 'GET',
    schema: {
      operationId: 'getHealthCheck',
      summary: 'Check application liveness',
      description: 'Returns a simple liveness payload for health probes.',
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
