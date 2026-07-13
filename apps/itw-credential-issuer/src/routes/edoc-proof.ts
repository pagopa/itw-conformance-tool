import { randomBytes } from 'node:crypto';

import { decodeJwt, decodeProtectedHeader, importJWK, jwtVerify } from 'jose';

import { makeOauthCallbacks } from '../plugins/index.js';

import type { FastifyPluginAsync, FastifyRequest } from 'fastify';

const isBase64 = (str: unknown): boolean => {
  if (typeof str !== 'string' || str.length === 0 || str.length % 4 !== 0) {
    return false;
  }
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(str)) {
    return false;
  }
  return Buffer.from(str, 'base64').toString('base64') === str;
};

const isBase64Url = (str: unknown): boolean => {
  if (typeof str !== 'string' || str.length === 0) {
    return false;
  }
  return /^[A-Za-z0-9_-]+$/.test(str);
};

const isBase64Like = (str: unknown): boolean => isBase64(str) || isBase64Url(str);

const isSessionExpired = (expiresAt: number): boolean => {
  const expiresAtMs = expiresAt > 1_000_000_000_000 ? expiresAt : expiresAt * 1000;
  return Date.now() > expiresAtMs;
};

interface EdocProofVerifyRequest {
  Body: {
    mrtd_auth_session: string;
    mrtd_pop_nonce: string;
    mrtd_validation_jwt: string;
  };
  Headers: {
    'oauth-client-attestation': string;
    'oauth-client-attestation-pop': string;
  };
}

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
    handler: async (request: FastifyRequest<EdocProofVerifyRequest>, reply) => {
      const { headers, body } = request;
      const { baseURL } = makeOauthCallbacks(app, request);

      try {
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

        let decodedAttestation;
        try {
          decodedAttestation = decodeJwt(headers['oauth-client-attestation']);
        } catch {
          return reply
            .code(400)
            .send({ error: 'invalid_request', error_description: 'Malformed oauth-client-attestation' });
        }

        try {
          const protectedHeader = decodeProtectedHeader(headers['oauth-client-attestation']);
          const validAttestationTyp =
            protectedHeader.typ === 'oauth-client-attestation+jwt' || protectedHeader.typ === 'wallet-attestation+jwt';
          if (!validAttestationTyp) {
            return reply.code(400).send({ error: 'invalid_request', error_description: 'Invalid attestation JWT typ' });
          }
        } catch {
          return reply
            .code(400)
            .send({ error: 'invalid_request', error_description: 'Invalid attestation JWT header' });
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
          const { payload: popPayload } = await jwtVerify(headers['oauth-client-attestation-pop'], walletPublicKey, {
            audience: baseURL,
            clockTolerance: 300,
            typ: 'oauth-client-attestation-pop+jwt'
          });

          if (popPayload.iss !== parRequest.client_id) {
            return reply
              .code(400)
              .send({ error: 'invalid_request', error_description: 'PoP issuer does not match PAR client_id' });
          }

          if (typeof popPayload.jti !== 'string' || popPayload.jti.length === 0) {
            return reply.code(400).send({ error: 'invalid_request', error_description: 'Missing PoP jti claim' });
          }
        } catch {
          return reply
            .code(400)
            .send({ error: 'invalid_request', error_description: 'Invalid oauth-client-attestation-pop signature' });
        }

        if (session.status !== 'pending_mrtd_verify') {
          return reply.code(400).send({ error: 'invalid_request', error_description: 'Invalid session state' });
        }

        const nowSeconds = Math.floor(Date.now() / 1000);
        if (isSessionExpired(session.expires_at)) {
          return reply.code(400).send({ error: 'invalid_request', error_description: 'Session expired' });
        }

        if (body.mrtd_pop_nonce !== session.mrtd_pop_nonce) {
          return reply.code(400).send({ error: 'invalid_request', error_description: 'Invalid mrtd_pop_nonce' });
        }

        if (session.mrtd_pop_nonce_consumed_at) {
          return reply.code(403).send({ error: 'access_denied', error_description: 'Nonce already consumed' });
        }

        let verifiedJwt;
        try {
          verifiedJwt = await jwtVerify(body.mrtd_validation_jwt, walletPublicKey, {
            audience: baseURL,
            clockTolerance: 300,
            typ: 'mrtd-ias+jwt'
          });
        } catch (err) {
          request.log.error({ err }, 'mrtd_validation_jwt verification failed');
          return reply
            .code(400)
            .send({ error: 'invalid_request', error_description: 'Invalid mrtd_validation_jwt signature or format' });
        }

        const header = verifiedJwt.protectedHeader;
        if (header.typ !== 'mrtd-ias+jwt' || !header.alg || !header.kid) {
          return reply.code(400).send({ error: 'invalid_request', error_description: 'Invalid JWT header' });
        }

        const payload = verifiedJwt.payload as Record<string, unknown>;

        if (!payload.iss || !payload.iat || !payload.exp) {
          return reply.code(400).send({ error: 'invalid_request', error_description: 'Missing base payload claims' });
        }

        if ((payload.exp as number) < nowSeconds) {
          return reply.code(400).send({ error: 'invalid_request', error_description: 'JWT expired' });
        }

        if (payload.document_type !== 'cie') {
          return reply.code(422).send({ error: 'invalid_document', error_description: 'Invalid document_type' });
        }

        const mrtd = payload.mrtd as Record<string, unknown> | undefined;
        if (!mrtd || !isBase64Like(mrtd.dg1) || !isBase64Like(mrtd.dg11) || !isBase64Like(mrtd.sod_mrtd)) {
          return reply
            .code(422)
            .send({ error: 'invalid_document', error_description: 'Invalid mrtd object or missing Base64 strings' });
        }

        const ias = payload.ias as Record<string, unknown> | undefined;
        if (!ias || !isBase64Like(ias.ias_pk) || !isBase64Like(ias.sod_ias) || !isBase64Like(ias.challenge_signed)) {
          return reply
            .code(422)
            .send({ error: 'invalid_document', error_description: 'Invalid ias object or missing Base64 strings' });
        }

        const claimedIdentity = payload.identity as Record<string, unknown> | undefined;
        if (claimedIdentity) {
          const hasMismatch =
            (typeof claimedIdentity.given_name === 'string' &&
              claimedIdentity.given_name !== session.identity.given_name) ||
            (typeof claimedIdentity.family_name === 'string' &&
              claimedIdentity.family_name !== session.identity.family_name) ||
            (typeof claimedIdentity.birthdate === 'string' &&
              claimedIdentity.birthdate !== session.identity.birthdate) ||
            (typeof claimedIdentity.personal_administrative_number === 'string' &&
              claimedIdentity.personal_administrative_number !== session.identity.personal_administrative_number);

          if (hasMismatch) {
            return reply
              .code(422)
              .send({ error: 'id_matching_failed', error_description: 'Identity mismatch with validated document' });
          }
        }

        session.status = 'verified';
        session.mrtd_pop_nonce_consumed_at = nowSeconds;
        const newNonce = randomBytes(16).toString('base64url');
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
