import { createHash } from 'node:crypto';

import { createObservedEvent } from '@itw-conformance-tool/conformance';

import type { FastifyPluginAsync } from 'fastify';

const sha256Base64Url = (value: string): string => createHash('sha256').update(value, 'utf8').digest('base64url');

const nonceRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/nonce',
    method: 'GET',
    schema: {
      operationId: 'getWalletNonce',
      summary: 'Retrieve a Wallet Solution nonce',
      description: 'Returns a cryptographically random, single-use nonce for Wallet Instance initialization.',
      tags: ['Wallet Solution'],
      produces: ['application/json'],
      response: {
        200: {
          type: 'object',
          required: ['nonce'],
          properties: {
            nonce: { type: 'string' }
          }
        }
      }
    },
    handler: async (request, reply) => {
      const nonce = app.walletNonces.issue();

      await app.conformanceEventSink?.emit(
        createObservedEvent({
          name: 'wallet_provider.nonce.requested',
          correlationId: request.conformance?.correlation?.correlationId ?? null,
          service: 'wallet-provider',
          requestId: request.id,
          diagnostic: {
            endpoint: '/nonce',
            method: 'GET',
            outcome: 'success',
            statusCode: 200,
            nonceSha256: sha256Base64Url(nonce)
          }
        })
      );

      return reply.code(200).header('cache-control', 'no-store').send({ nonce });
    }
  });
};

export default nonceRoute;
