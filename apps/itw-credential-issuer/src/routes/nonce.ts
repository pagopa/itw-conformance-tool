import { createHash } from 'node:crypto';

import { createObservedEvent } from '@itw-conformance-tool/conformance';

import { NonceService } from '../domain/index.js';

import type { FastifyPluginAsync } from 'fastify';

const sha256Base64Url = (value: string): string => createHash('sha256').update(value, 'utf8').digest('base64url');

const nonceRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/nonce',
    method: 'POST',
    schema: {
      tags: ['Credential']
    },
    handler: async (request, reply) => {
      try {
        const service = new NonceService(app.nonceRepository);
        const nonce = await service.generate();

        await app.conformanceEventSink?.emit(
          createObservedEvent({
            name: 'issuer.nonce.requested',
            correlationId: request.conformance?.correlation?.correlationId ?? null,
            service: 'credential-issuer',
            requestId: request.id,
            diagnostic: {
              endpoint: '/nonce',
              method: 'POST',
              cNonceSha256: sha256Base64Url(nonce)
            }
          })
        );

        return reply
          .code(200)
          .headers({
            'Cache-Control': 'no-store',
            'Content-Type': 'application/json'
          })
          .send({ c_nonce: nonce });
      } catch (error) {
        app.log.error({ err: error }, 'Nonce generation failed');
        return reply.code(500).send({ error: 'internal_server_error' });
      }
    }
  });
};

export default nonceRoute;
