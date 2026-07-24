import path from 'node:path';

import FastifyAutoLoad from '@fastify/autoload';
import Fastify, { type FastifyInstance, type FastifyPluginOptions } from 'fastify';

export default async function bootstrap(app: FastifyInstance, opts: FastifyPluginOptions) {
  app.register(FastifyAutoLoad, {
    dir: path.join(import.meta.dirname, 'plugins'),
    autoHooks: true,
    autoHooksPattern: /\.hook(?:\.ts|\.js|\.cjs|\.mjs)$/i,
    cascadeHooks: true,
    options: { ...opts }
  });

  app.register(FastifyAutoLoad, {
    dir: path.join(import.meta.dirname, 'routes'),
    autoHooks: true,
    autoHooksPattern: /\.hook(?:\.ts|\.js|\.cjs|\.mjs)$/i,
    cascadeHooks: true,
    options: { ...opts }
  });

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
      const message = err.statusCode && err.statusCode < 500 ? err.message : 'Internal Server Error';
      reply.send({ message });
    } else {
      reply.send(err);
    }
  });

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
