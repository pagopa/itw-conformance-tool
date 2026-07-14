import { DeferredCredentialAuthError, DeferredCredentialService, InvalidTransactionIdError } from '../domain/index.js';
import { makeOauthCallbacks } from '../plugins/index.js';

import type { HttpMethod } from '@pagopa/io-wallet-utils';
import type { FastifyPluginAsync } from 'fastify';

const deferredRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/deferred',
    method: 'POST',
    schema: {
      tags: ['Credential'],
      body: {
        type: 'object',
        properties: {
          transaction_id: { type: 'string', minLength: 1 }
        },
        required: ['transaction_id'],
        additionalProperties: false
      }
    },
    handler: async (request, reply) => {
      const body = typeof request.body === 'string' ? request.body : JSON.stringify(request.body ?? {});
      const { baseURL, headers, oauthCallbacks, sdkConfig } = makeOauthCallbacks(app, request);

      reply.header('Cache-Control', 'no-store');

      try {
        const service = new DeferredCredentialService(app.deferredCredentialRepository);
        const result = await service.retrieveDeferredCredential({
          body,
          callbacks: {
            hash: oauthCallbacks.hash,
            verifyJwt: oauthCallbacks.verifyJwt
          },
          config: sdkConfig,
          headers,
          method: request.method as HttpMethod,
          url: `${baseURL}${request.url}`
        });

        return reply.code(200).send(result.credentialResponse ?? result);
      } catch (error) {
        if (error instanceof InvalidTransactionIdError) {
          return reply.code(400).send({ error: 'invalid_transaction_id', error_description: error.message });
        }

        if (error instanceof DeferredCredentialAuthError) {
          return reply.code(400).send({ error: 'invalid_or_missing_proof', error_description: error.message });
        }

        request.log.error({ err: error }, 'Deferred credential retrieval failed');
        return reply.code(500).send({ error: 'internal_server_error' });
      }
    }
  });
};

export default deferredRoute;
