import path from 'node:path';

import FastifyAutoLoad from '@fastify/autoload';
import Fastify, { type FastifyInstance, type FastifyPluginOptions } from 'fastify';

import configPlugin from './plugins/config.js';
import dbPlugin from './plugins/db.js';
import corsPlugin, { autoConfig as corsConfig } from './plugins/external/cors.js';
import helmetPlugin, { autoConfig as helmetConfig } from './plugins/external/helmet.js';
import rateLimitPlugin, { autoConfig as rateLimitConfig } from './plugins/external/rate-limit.js';
import sensiblePlugin from './plugins/external/sensible.js';
import swaggerPlugin from './plugins/external/swagger.js';
import keysPlugin from './plugins/keys.js';

export default async function bootstrap(app: FastifyInstance, opts: FastifyPluginOptions) {
  await app.register(configPlugin);
  await app.register(dbPlugin);
  await app.register(keysPlugin);

  await app.register(corsPlugin, corsConfig);
  await app.register(helmetPlugin, helmetConfig);
  await app.register(rateLimitPlugin, rateLimitConfig);
  await app.register(sensiblePlugin);
  await app.register(swaggerPlugin);

  // Auto-load routes
  app.register(FastifyAutoLoad, {
    dir: path.join(import.meta.dirname, 'routes'),
    autoHooks: true,
    autoHooksPattern: /\.hook(?:\.ts|\.js|\.cjs|\.mjs)$/i,
    cascadeHooks: true,
    options: { ...opts }
  });

  // Set error handler
  app.setErrorHandler(function (err, request, reply) {
    if (err instanceof Fastify.errorCodes.FST_ERR_BAD_STATUS_CODE) {
      this.log.error(
        {
          err,
          request: {
            method: request.method,
            url: request.url,
            query: request.query,
            params: request.params
          }
        },
        'Unhandled error occurred'
      );

      reply.code(err.statusCode ?? 500);

      let message = 'Internal Server Error';
      if (err.statusCode && err.statusCode < 500) {
        message = err.message;
      }

      reply.send({ message });
    } else {
      reply.send(err);
    }
  });

  // This is used to avoid attacks to find valid routes
  app.setNotFoundHandler((request, reply) => {
    request.log.warn(
      {
        request: {
          method: request.method,
          url: request.url,
          query: request.query,
          params: request.params
        }
      },
      'Resource not found'
    );

    reply.code(404);

    return { message: 'Not Found' };
  });
}
