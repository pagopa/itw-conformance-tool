import path from 'node:path';

import FastifyAutoLoad from '@fastify/autoload';
import Fastify, { type FastifyPluginAsync } from 'fastify';
import fp from 'fastify-plugin';

/**
 * Test files sit beside the code they cover. They are stripped from the built
 * output, so autoload never meets them in production — but a test that boots
 * this app from source would otherwise have them registered as plugins, and a
 * test file is not one.
 */
const TEST_FILE_PATTERN = /(?:^|\/)tests(?:\/|$)|\.(?:test|spec)\.[cm]?[jt]s$/;

const bootstrap: FastifyPluginAsync = async (app, opts) => {
  // Auto-load plugins
  await app.register(FastifyAutoLoad, {
    dir: path.join(import.meta.dirname, 'plugins'),
    dirNameRoutePrefix: false,
    ignorePattern: TEST_FILE_PATTERN,
    options: { ...opts }
  });

  // Auto-load routes
  await app.register(FastifyAutoLoad, {
    dir: path.join(import.meta.dirname, 'routes'),
    autoHooks: true,
    autoHooksPattern: /\.hook(?:\.ts|\.js|\.cjs|\.mjs)$/i,
    cascadeHooks: true,
    ignorePattern: TEST_FILE_PATTERN,
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
};

export default fp(bootstrap);
