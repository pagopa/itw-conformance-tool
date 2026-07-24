import { randomBytes } from 'node:crypto';

import { createObservedEvent } from '@itw-conformance-tool/conformance';
import { parseAuthorizationResponse, type Openid4vpAuthorizationRequestPayload } from '@pagopa/io-wallet-oid4vp';
import { decodeJwt } from 'jose';
import z from 'zod';

import { toResult } from '../utils/result.js';
import { VpTokenVerifier } from '../utils/vp-token.js';

import type { FastifyReply, FastifyRequest } from 'fastify';

const errorSchema = z.enum([
  'invalid_request_uri',
  'vp_formats_not_supported',
  'invalid_request_uri_method',
  'invalid_request',
  'access_denied',
  'invalid_client',
  'invalid_transaction_data'
]);

const responseBodySchema = z.object({
  response: z.string().min(1).describe('direct_post.jwt authorization response payload returned by the wallet.'),
  state: z.uuid().optional().describe('Wallet session state identifier.')
});

const errorResponseBodySchema = z.object({
  error: errorSchema.describe('OpenID4VP authorization error code.'),
  error_description: z.string().optional().describe('Human-readable authorization error details.'),
  state: z.uuid().optional().describe('Wallet session state identifier.')
});

export const authorizationResponsePayloadSchema = z.union([responseBodySchema, errorResponseBodySchema]);
type AuthorizationResponsePayload = z.infer<typeof authorizationResponsePayloadSchema>;

export const authorizationResponseResultSchema = z.object({
  redirect_uri: z.url().describe('Absolute browser redirect URI to continue the relying-party flow.')
});

export const sessionIdQuerystringSchema = z.object({
  session_id: z.uuid().describe('Identifier binding the callback to the original authorization request.')
});

type SessionIdQuerystring = z.infer<typeof sessionIdQuerystringSchema>;

export const getAuthorizationResponseHandler = async (
  req: FastifyRequest<{
    Body: AuthorizationResponsePayload;
    Querystring: SessionIdQuerystring;
  }>,
  reply: FastifyReply
): Promise<FastifyReply> => {
  const requestObjectRepository = req.server.repository.requestObject;
  const authorizationRequest = requestObjectRepository.getBySessionId(req.query.session_id);
  const correlationId = authorizationRequest.id;

  await req.server.conformanceEventSink.emit(
    createObservedEvent({
      name: 'rp.presentation_response.received',
      scenarioId: req.conformance?.correlation?.scenarioId ?? null,
      correlationId,
      service: 'relying-party',
      requestId: req.id,
      diagnostic: { endpoint: '/auth/response' }
    })
  );

  if ('error' in req.body) {
    requestObjectRepository.update(authorizationRequest.id, 'rejected');
    return reply.status(200).send();
  }

  const authorizationRequestPayload = decodeJwt<Openid4vpAuthorizationRequestPayload>(authorizationRequest.jwt);

  const authResponseResult = await toResult(
    parseAuthorizationResponse({
      callbacks: req.server.callbacks,
      authorizationResponse: req.body,
      authorizationRequestPayload
    })
  );

  if (!authResponseResult.ok) {
    requestObjectRepository.update(authorizationRequest.id, 'rejected');
    req.log.error({ error: authResponseResult.error }, 'Error parsing authorization response');
    return reply.status(400).send({ error: 'invalid_request', error_description: authResponseResult.error.message });
  }

  const verifier = new VpTokenVerifier({
    authResponse: authResponseResult.value,
    iacaX509: req.server.config.IACA_X509,
    requestObject: authorizationRequestPayload,
    verifierEncryptionPublicJwk: req.server.jwks.enc.public
  });

  const verificationResult = await toResult(verifier.verifyCredentials());
  if (!verificationResult.ok) {
    await req.server.conformanceEventSink.emit(
      createObservedEvent({
        name: 'vp_token.validation.failed',
        scenarioId: req.conformance?.correlation?.scenarioId ?? null,
        correlationId,
        service: 'relying-party',
        requestId: req.id,
        validation: { reason: verificationResult.error.message }
      })
    );

    requestObjectRepository.update(authorizationRequest.id, 'rejected');
    req.log.error({ error: verificationResult.error }, 'Error verifying credentials');
    return reply.status(403).send({ error: 'invalid_request', error_description: verificationResult.error.message });
  }

  await req.server.conformanceEventSink.emit(
    createObservedEvent({
      name: 'vp_token.validation.succeeded',
      scenarioId: req.conformance?.correlation?.scenarioId ?? null,
      correlationId,
      service: 'relying-party',
      requestId: req.id
    })
  );

  const redirectUri = new URL(`${req.server.config.BASE_URL}/callback/${authorizationRequest.id}`);
  const responseCode = randomBytes(32).toString('hex');
  redirectUri.searchParams.set('response_code', responseCode);
  requestObjectRepository.update(authorizationRequest.id, 'verified', redirectUri.toString(), verificationResult.value);

  return reply.status(200).send({ redirect_uri: redirectUri.toString() });
};
