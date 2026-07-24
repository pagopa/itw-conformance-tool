import fastifySwagger from '@fastify/swagger';
import fastifySwaggerUi from '@fastify/swagger-ui';
import fp from 'fastify-plugin';

export default fp(async function (fastify) {
  await fastify.register(fastifySwagger, {
    hideUntagged: true,
    openapi: {
      info: {
        title: 'IT Wallet Provider API',
        description: 'Local IT Wallet Wallet Provider helper service',
        version: '0.0.0'
      }
    }
  });

  await fastify.register(fastifySwaggerUi, {
    routePrefix: '/api/docs'
  });
});
