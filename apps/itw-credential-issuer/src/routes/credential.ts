import { CreateCredentialError, CredentialService, InvalidProofError } from '../domain/index.js';
import { makeJwksRepository, makeOauthCallbacks } from '../plugins/index.js';

import type { HttpMethod } from '@pagopa/io-wallet-utils';
import type { FastifyPluginAsync } from 'fastify';

const credentialRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/credential',
    method: 'POST',
    schema: {
      tags: ['Credential']
    },
    handler: async (request, reply) => {
      const body = typeof request.body === 'string' ? request.body : JSON.stringify(request.body ?? {});
      const { baseURL, headers, oauthCallbacks, sdkConfig } = makeOauthCallbacks(app, request);

      reply.header('Cache-Control', 'no-store');

      try {
        const service = new CredentialService(
          makeJwksRepository(app),
          app.nonceRepository,
          app.deferredCredentialRepository
        );
        const result = await service.createCredential({
          baseURL,
          batchIssuanceByDeferred: app.config.BATCH_ISSUANCE_BY_DEFERRED,
          body,
          callbacks: {
            hash: oauthCallbacks.hash,
            verifyJwt: oauthCallbacks.verifyJwt
          },
          config: sdkConfig,
          headers,
          method: request.method as HttpMethod,
          trustedWalletProviderIssuers: app.config.TRUSTED_WALLET_PROVIDER_ISSUERS,
          url: `${baseURL}${request.url}`
        });

        const statusCode = result.status === 'deferred' ? 202 : 200;
        return reply.code(statusCode).send(result.sdkResult.credentialResponse ?? result.sdkResult);
      } catch (error) {
        if (error instanceof InvalidProofError) {
          return reply.code(400).send({ error: 'invalid_or_missing_proof', error_description: error.message });
        }

        if (error instanceof CreateCredentialError) {
          return reply.code(400).send({ error: 'invalid_request', error_description: error.message });
        }

        request.log.error({ err: error }, 'Credential issuance failed');
        return reply.code(500).send({ error: 'internal_server_error' });
      }
    }
  });
};

export default credentialRoute;
