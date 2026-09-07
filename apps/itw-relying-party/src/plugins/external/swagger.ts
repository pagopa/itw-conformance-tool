import fastifySwagger from '@fastify/swagger';
import fastifySwaggerUi from '@fastify/swagger-ui';
import fp from 'fastify-plugin';

export const swaggerDocsRoutePrefix = '/api/docs';

export default fp(async function (fastify) {
  await fastify.register(fastifySwagger, {
    hideUntagged: true,
    openapi: {
      openapi: '3.0.3',
      info: {
        title: 'IT Wallet Relying Party',
        description:
          'OpenAPI documentation for the Relying Party demo service, aligned with version 1.4 of the IT Wallet specification.',
        version: '1.0.0'
      },
      tags: [
        {
          name: 'Authorization',
          description: 'Request-object creation and wallet response exchange.'
        },
        {
          name: 'Status',
          description: 'Polling endpoints for wallet session state.'
        },
        {
          name: 'Entity Configuration',
          description: 'OpenID Federation entity statement discovery.'
        },
        {
          name: 'Health',
          description: 'Application liveness checks.'
        }
      ]
    }
  });

  await fastify.register(fastifySwaggerUi, {
    routePrefix: swaggerDocsRoutePrefix
  });
});
