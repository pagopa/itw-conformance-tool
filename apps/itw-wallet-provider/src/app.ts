import path from 'node:path';

import FastifyAutoLoad from '@fastify/autoload';
import Fastify, { type FastifyInstance, type FastifyPluginOptions, type FastifyReply } from 'fastify';

function isWalletInstanceManagementRequest(url: string): boolean {
  return url.split('?', 1)[0] === '/wallet-instances';
}

function getErrorStatusCode(error: unknown): number | undefined {
  if (typeof error !== 'object' || error === null || !('statusCode' in error)) {
    return undefined;
  }

  const statusCode = error.statusCode;

  return typeof statusCode === 'number' ? statusCode : undefined;
}

function sendWalletInstanceManagementError(
  reply: FastifyReply,
  statusCode: number,
  error: string,
  errorDescription: string
) {
  return reply.code(statusCode).header('cache-control', 'no-store').send({
    error,
    error_description: errorDescription
  });
}

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
    if (isWalletInstanceManagementRequest(request.url)) {
      const statusCode = getErrorStatusCode(err) ?? 500;

      if (statusCode === 400) {
        return sendWalletInstanceManagementError(
          reply,
          400,
          'bad_request',
          'The request is malformed, missing required parameters, or includes invalid and unknown parameters.'
        );
      }

      if (statusCode === 503) {
        return sendWalletInstanceManagementError(
          reply,
          503,
          'temporarily_unavailable',
          'The service is unavailable. Please try again later.'
        );
      }

      return sendWalletInstanceManagementError(
        reply,
        500,
        'server_error',
        'An internal error occurred while processing the request.'
      );
    }

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
      return reply.send({ message });
    } else {
      return reply.send(err);
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
