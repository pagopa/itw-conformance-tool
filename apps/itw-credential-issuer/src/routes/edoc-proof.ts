import { randomBytes } from 'node:crypto';

import { decodeJwt, importJWK, jwtVerify } from 'jose';

import { makeOauthCallbacks } from '../plugins/index.js';

import type { FastifyPluginAsync } from 'fastify';

const isBase64 = (str: unknown): boolean => {
  if (typeof str !== 'string' || str.length === 0 || str.length % 4 !== 0) {
    return false;
  }
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(str)) {
    return false;
  }
  try {
    return Buffer.from(str, 'base64').toString('base64') === str;
  } catch {
    return false;
  }
};

const edocProofVerifyRoute: FastifyPluginAsync = async (app) => {
  const rateLimit = app.rateLimit({ max: 100, timeWindow: '1 minute' });
  app.route({
    url: '/edoc-proof/verify',
    method: 'POST',
    onRequest: [rateLimit],
    schema: {
      tags: ['EDoc Proof'],
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
        required: ['mrtd_auth_session', 'mrtd_pop_nonce', 'mrtd_validation_jwt'],
        properties: {
          mrtd_auth_session: { type: 'string' },
          mrtd_pop_nonce: { type: 'string' },
          mrtd_validation_jwt: { type: 'string' }
        }
      }
    },
    handler: async (request, reply) => {
      const headers = request.headers as {
        'oauth-client-attestation': string;
        'oauth-client-attestation-pop': string;
      };
      const body = request.body as {
        mrtd_auth_session: string;
        mrtd_pop_nonce: string;
        mrtd_validation_jwt: string;
      };

      try {
        let decodedAttestation;
        try {
          decodedAttestation = decodeJwt(headers['oauth-client-attestation']);
        } catch {
          return reply
            .code(400)
            .send({ error: 'invalid_request', error_description: 'Malformed oauth-client-attestation' });
        }

        const walletJwk = (decodedAttestation.cnf as Record<string, unknown>)?.jwk as
          | Record<string, unknown>
          | undefined;

        if (!walletJwk) {
          return reply
            .code(400)
            .send({ error: 'invalid_request', error_description: 'Missing wallet JWK in attestation' });
        }

        let walletPublicKey;
        try {
          walletPublicKey = await importJWK(walletJwk, 'ES256');
        } catch {
          return reply.code(400).send({ error: 'invalid_request', error_description: 'Invalid wallet JWK format' });
        }

        try {
          await jwtVerify(headers['oauth-client-attestation-pop'], walletPublicKey);
        } catch {
          return reply
            .code(400)
            .send({ error: 'invalid_request', error_description: 'Invalid oauth-client-attestation-pop signature' });
        }

        const parEntry = await app.parRepository.getByMrtdAuthSession(body.mrtd_auth_session);
        if (!parEntry) {
          return reply.code(400).send({ error: 'invalid_request', error_description: 'Session not found or expired' });
        }

        let parRequest;
        try {
          parRequest = JSON.parse(parEntry.requestObject);
        } catch {
          return reply.code(400).send({ error: 'invalid_request', error_description: 'Corrupted session data' });
        }

        const session = parRequest.mrtd_auth_session;
        if (!session) {
          return reply.code(400).send({ error: 'invalid_request', error_description: 'Session invalid' });
        }

        if (session.status !== 'pending_mrtd_verify') {
          return reply.code(400).send({ error: 'invalid_request', error_description: 'Invalid session state' });
        }

        const now = Math.floor(Date.now() / 1000);
        if (session.expires_at < now) {
          return reply.code(400).send({ error: 'invalid_request', error_description: 'Session expired' });
        }

        if (body.mrtd_pop_nonce !== session.mrtd_pop_nonce) {
          return reply.code(400).send({ error: 'invalid_request', error_description: 'Invalid mrtd_pop_nonce' });
        }

        if (session.mrtd_pop_nonce_consumed_at) {
          return reply.code(400).send({ error: 'invalid_request', error_description: 'Nonce already consumed' });
        }

        let verifiedJwt;
        try {
          verifiedJwt = await jwtVerify(body.mrtd_validation_jwt, walletPublicKey);
        } catch (err) {
          const errorMessage = err instanceof Error ? err.message : 'Unknown signature error';
          return reply
            .code(400)
            .send({ error: 'invalid_request', error_description: `Invalid mrtd_validation_jwt: ${errorMessage}` });
        }

        const header = verifiedJwt.protectedHeader;
        if (header.typ !== 'mrtd-ias+jwt' || !header.alg || !header.kid) {
          return reply.code(400).send({ error: 'invalid_request', error_description: 'Invalid JWT header' });
        }

        const payload = verifiedJwt.payload as Record<string, unknown>;
        const { baseURL } = makeOauthCallbacks(app, request);

        if (!payload.iss || !payload.aud || !payload.iat || !payload.exp) {
          return reply.code(400).send({ error: 'invalid_request', error_description: 'Missing base payload claims' });
        }

        const isValidAudience =
          (typeof payload.aud === 'string' && payload.aud === baseURL) ||
          (Array.isArray(payload.aud) && payload.aud.includes(baseURL));

        if (!isValidAudience) {
          return reply.code(400).send({ error: 'invalid_request', error_description: 'Invalid audience' });
        }

        if ((payload.exp as number) < now) {
          return reply.code(400).send({ error: 'invalid_request', error_description: 'JWT expired' });
        }

        if (payload.document_type !== 'cie') {
          return reply.code(400).send({ error: 'invalid_request', error_description: 'Invalid document_type' });
        }

        const mrtd = payload.mrtd as Record<string, unknown> | undefined;
        if (!mrtd || !isBase64(mrtd.dg1) || !isBase64(mrtd.dg11) || !isBase64(mrtd.sod_mrtd)) {
          return reply
            .code(400)
            .send({ error: 'invalid_request', error_description: 'Invalid mrtd object or missing Base64 strings' });
        }

        const ias = payload.ias as Record<string, unknown> | undefined;
        if (!ias || !isBase64(ias.ias_pk) || !isBase64(ias.sod_ias) || !isBase64(ias.challenge_signed)) {
          return reply
            .code(400)
            .send({ error: 'invalid_request', error_description: 'Invalid ias object or missing Base64 strings' });
        }

        session.status = 'verified';
        session.mrtd_pop_nonce_consumed_at = now;
        const newNonce = randomBytes(16).toString('hex');
        session.mrtd_val_pop_nonce = newNonce;

        await app.parRepository.update(parEntry.requestUri, { requestObject: JSON.stringify(parRequest) });

        return reply.code(202).send({
          status: 'require_interaction',
          type: 'redirect_to_web',
          redirect_uri: `${baseURL}/idp/callback?mrtd_auth_session=${session.mrtd_auth_session}`,
          mrtd_val_pop_nonce: newNonce
        });
      } catch (error) {
        request.log.error({ err: error }, 'EDoc Proof verify failed');
        return reply.code(500).send({ error: 'internal_server_error' });
      }
    }
  });
};

export default edocProofVerifyRoute;
