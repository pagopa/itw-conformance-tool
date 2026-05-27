import { randomBytes } from 'node:crypto';

import { decodeJwt, importJWK, jwtVerify } from 'jose';

import { makeOauthCallbacks } from '../plugins/index.js';

import type { FastifyPluginAsync } from 'fastify';

const edocProofVerifyRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/edoc-proof/verify',
    method: 'POST',
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
        // 1. Extract and validate Wallet Public Key from Attestation
        const decodedAttestation = decodeJwt(headers['oauth-client-attestation']);
        const walletJwk = (decodedAttestation.cnf as Record<string, unknown>)?.jwk as Record<string, unknown> | undefined;
        if (!walletJwk) {
          return reply.code(400).send({ error: 'invalid_request', error_description: 'Missing wallet JWK in attestation' });
        }
        const walletPublicKey = await importJWK(walletJwk, 'ES256');

        // Verify PoP signature with the derived key
        await jwtVerify(headers['oauth-client-attestation-pop'], walletPublicKey);

        // 2. Verify Session exists, is not expired and in correct state
        const parEntry = await app.parRepository.getByMrtdAuthSession(body.mrtd_auth_session);
        if (!parEntry) {
          return reply.code(400).send({ error: 'invalid_request', error_description: 'Session not found or expired' });
        }

        const parRequest = JSON.parse(parEntry.requestObject);
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

        // 3. Nonce Chaining and Anti-Replay
        if (body.mrtd_pop_nonce !== session.mrtd_pop_nonce) {
          return reply.code(400).send({ error: 'invalid_request', error_description: 'Invalid mrtd_pop_nonce' });
        }
        
        if (session.mrtd_pop_nonce_consumed_at) {
          return reply.code(400).send({ error: 'invalid_request', error_description: 'Nonce already consumed' });
        }

        // Consume nonce
        session.mrtd_pop_nonce_consumed_at = now;
        await app.parRepository.update(parEntry.requestUri, { requestObject: JSON.stringify(parRequest) });

        // 4. Validate mrtd_validation_jwt schema
        let verifiedJwt;
        try {
          verifiedJwt = await jwtVerify(body.mrtd_validation_jwt, walletPublicKey);
        } catch {
          return reply.code(400).send({ error: 'invalid_request', error_description: 'Invalid mrtd_validation_jwt signature' });
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

        if (payload.aud !== baseURL) {
          return reply.code(400).send({ error: 'invalid_request', error_description: 'Invalid audience' });
        }

        if (payload.exp < now) {
          return reply.code(400).send({ error: 'invalid_request', error_description: 'JWT expired' });
        }

        if (payload.document_type !== 'cie') {
          return reply.code(400).send({ error: 'invalid_request', error_description: 'Invalid document_type' });
        }

        const mrtd = payload.mrtd as Record<string, unknown> | undefined;
        if (!mrtd || typeof mrtd.dg1 !== 'string' || !mrtd.dg1 || typeof mrtd.dg11 !== 'string' || !mrtd.dg11 || typeof mrtd.sod_mrtd !== 'string' || !mrtd.sod_mrtd) {
          return reply.code(400).send({ error: 'invalid_request', error_description: 'Invalid mrtd object' });
        }

        const ias = payload.ias as Record<string, unknown> | undefined;
        if (!ias || typeof ias.ias_pk !== 'string' || !ias.ias_pk || typeof ias.sod_ias !== 'string' || !ias.sod_ias || typeof ias.challenge_signed !== 'string' || !ias.challenge_signed) {
          return reply.code(400).send({ error: 'invalid_request', error_description: 'Invalid ias object' });
        }

        // 5. Transizione di Stato e Risposta
        session.status = 'verified';
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
