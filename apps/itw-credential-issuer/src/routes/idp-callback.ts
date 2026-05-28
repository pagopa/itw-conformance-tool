import { randomUUID } from 'node:crypto';

import { importJWK, jwtVerify, type JWK } from 'jose';

import type { FastifyPluginAsync, FastifyRequest } from 'fastify';

interface IdpCallbackQuerystring {
  mrtd_auth_session: string;
  mrtd_val_pop_nonce: string;
}

const idpCallbackRoute: FastifyPluginAsync = async (app) => {
  const rateLimit = app.rateLimit({ max: 100, timeWindow: '1 minute' });
  app.route({
    url: '/idp/callback',
    method: 'GET',
    onRequest: [rateLimit],
    schema: {
      tags: ['EDoc Proof'],
      querystring: {
        type: 'object',
        required: ['mrtd_auth_session', 'mrtd_val_pop_nonce'],
        properties: {
          mrtd_auth_session: { type: 'string' },
          mrtd_val_pop_nonce: { type: 'string' }
        }
      }
    },
    handler: async (request: FastifyRequest<{ Querystring: IdpCallbackQuerystring }>, reply) => {
      const { mrtd_auth_session, mrtd_val_pop_nonce } = request.query;
      const baseURL = `${app.config.BASE_URL_SCHEME}://${app.config.HOST}:${app.config.PORT}`;

      try {
        const parEntry = await app.parRepository.getByMrtdAuthSession(mrtd_auth_session);
        if (!parEntry) {
          return reply.code(400).send({ error: 'invalid_request', error_description: 'Session not found or expired' });
        }

        const parRequest = await JSON.parse(parEntry.requestObject);

        const session = parRequest.mrtd_auth_session;
        if (!session) {
          return reply.code(400).send({ error: 'invalid_request', error_description: 'Session invalid' });
        }

        if (session.status !== 'verified') {
          const statusCode = session.status === 'completed' ? 403 : 400;
          const errorCode = statusCode === 403 ? 'access_denied' : 'invalid_request';
          return reply
            .code(statusCode)
            .send({ error: errorCode, error_description: `Invalid session state: ${session.status}` });
        }

        if (Date.now() > session.expires_at) {
          return reply.code(400).send({ error: 'invalid_request', error_description: 'Session expired' });
        }

        if (session.mrtd_val_pop_nonce_consumed_at !== undefined) {
          return reply.code(403).send({ error: 'access_denied', error_description: 'Nonce already consumed' });
        }

        const walletPublicKeyJwk = session.wallet_public_key as JWK | undefined;
        if (!walletPublicKeyJwk) {
          return reply
            .code(400)
            .send({ error: 'invalid_request', error_description: 'Missing wallet public key in session' });
        }

        let walletPublicKey;
        try {
          walletPublicKey = await importJWK(walletPublicKeyJwk, walletPublicKeyJwk.alg ?? 'ES256');
        } catch {
          return reply
            .code(400)
            .send({ error: 'invalid_request', error_description: 'Invalid wallet public key in session' });
        }

        let jwtPayload;
        try {
          const { payload } = await jwtVerify(mrtd_val_pop_nonce, walletPublicKey, {
            audience: baseURL,
            clockTolerance: 30
          });
          jwtPayload = payload;
        } catch (err) {
          request.log.error({ err }, 'mrtd_val_pop_nonce JWT verification failed');
          return reply
            .code(400)
            .send({ error: 'invalid_request', error_description: 'Invalid mrtd_val_pop_nonce JWT' });
        }

        if (!jwtPayload['iat'] || !jwtPayload['exp']) {
          return reply
            .code(400)
            .send({ error: 'invalid_request', error_description: 'mrtd_val_pop_nonce JWT must include iat and exp' });
        }

        if (jwtPayload['nonce'] !== session.mrtd_val_pop_nonce) {
          return reply
            .code(400)
            .send({ error: 'invalid_request', error_description: 'mrtd_val_pop_nonce does not match issued nonce' });
        }

        const code = randomUUID();
        const codeExpiresAt = Math.floor(Date.now() / 1000) + 60;
        const now = Math.floor(Date.now() / 1000);

        session.status = 'completed';
        session.mrtd_val_pop_nonce_consumed_at = now;

        parRequest.code = code;
        parRequest.code_consumed_at = undefined;
        parRequest.code_expires_at = codeExpiresAt;

        await app.parRepository.update(parEntry.requestUri, { requestObject: JSON.stringify(parRequest) });

        const location = new URL(parRequest.redirect_uri);
        location.searchParams.set('code', code);
        location.searchParams.set('state', parRequest.state);
        location.searchParams.set('iss', baseURL);

        return reply.code(302).header('Location', location.toString()).send();
      } catch (error) {
        request.log.error({ err: error }, 'IdP callback failed');
        return reply.code(500).send({ error: 'internal_server_error' });
      }
    }
  });
};

export default idpCallbackRoute;
