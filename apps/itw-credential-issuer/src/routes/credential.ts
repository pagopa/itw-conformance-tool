import { CreateCredentialError, CredentialService, InvalidProofError } from '@itw-conformance-tool/issuer';

import { makeJwksRepository, makeOauthCallbacks } from '../plugins/index.js';

import type { HttpMethod } from '@pagopa/io-wallet-utils';
import type { FastifyPluginAsync } from 'fastify';

const credentialRoute: FastifyPluginAsync = async (app) => {
  const rateLimit = app.rateLimit({ max: 100, timeWindow: '15 minutes' });
  app.route({
    url: '/credential',
    method: 'POST',
    onRequest: [rateLimit],
    schema: {
      tags: ['Credential']
    },
    handler: async (request, reply) => {
      const body = typeof request.body === 'string' ? request.body : JSON.stringify(request.body ?? {});
      const { baseURL, headers, oauthCallbacks, sdkConfig } = makeOauthCallbacks(app, request);

      try {
        const service = new CredentialService(makeJwksRepository(app), app.nonceRepository);
        const result = await service.createCredential({
          baseURL,
          body,
          callbacks: {
            hash: oauthCallbacks.hash,
            verifyJwt: oauthCallbacks.verifyJwt
          },
          config: sdkConfig,
          headers,
          method: request.method as HttpMethod,
          url: request.url
        });

        return reply.code(200).send(result);
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
