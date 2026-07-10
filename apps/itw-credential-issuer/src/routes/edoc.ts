import { EdocProofInitError, EdocProofService } from '@itw-conformance-tool/issuer';

import { makeEdocParRepository, makeJwksRepository } from '../plugins/index.js';

import type { FastifyPluginAsync } from 'fastify';

interface EdocProofInitBody {
  mrtd_auth_session: string;
  mrtd_pop_jwt_nonce: string;
}

interface EdocProofInitHeaders {
  'oauth-client-attestation': string;
  'oauth-client-attestation-pop': string;
}

const EdocInit: FastifyPluginAsync = async (app) => {
  const rateLimit = app.rateLimit({ max: 100, timeWindow: '15 minutes' });
  app.route<{ Body: EdocProofInitBody; Headers: EdocProofInitHeaders }>({
    url: '/edoc-proof/init',
    method: 'POST',
    onRequest: [rateLimit],
    schema: {
      tags: ['Edoc'],
      headers: {
        type: 'object',
        required: ['oauth-client-attestation', 'oauth-client-attestation-pop'],
        properties: {
          'oauth-client-attestation': { type: 'string' },
          'oauth-client-attestation-pop': { type: 'string' }
        }
      },
      body: {
        type: 'object',
        required: ['mrtd_auth_session', 'mrtd_pop_jwt_nonce'],
        properties: {
          mrtd_auth_session: { type: 'string' },
          mrtd_pop_jwt_nonce: { type: 'string' }
        }
      }
    },
    handler: async (request, reply) => {
      const { mrtd_auth_session, mrtd_pop_jwt_nonce } = request.body;
      const clientAttestationJwt = request.headers['oauth-client-attestation'];
      const clientAttestationPopJwt = request.headers['oauth-client-attestation-pop'];

      try {
        const service = new EdocProofService(makeEdocParRepository(app), makeJwksRepository(app));
        const responseJwt = await service.processInit({
          baseURL: app.config.BASE_URL,
          clientAttestationJwt,
          clientAttestationPopJwt,
          mrtdAuthSessionId: mrtd_auth_session,
          mrtdPopJwtNonce: mrtd_pop_jwt_nonce
        });

        return reply.code(202).header('Content-Type', 'application/jwt; charset=utf-8').send(responseJwt);
      } catch (error) {
        if (error instanceof EdocProofInitError) {
          const errorCode =
            error.statusCode === 401
              ? 'invalid_client'
              : error.statusCode === 403
                ? 'access_denied'
                : 'invalid_request';
          return reply.code(error.statusCode).send({
            error: errorCode,
            error_description: error.message
          });
        }

        request.log.error({ err: error }, 'Edoc proof init failed');
        return reply.code(503).send({ error: 'temporarily_unavailable' });
      }
    }
  });
};

export default EdocInit;
