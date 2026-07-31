import { randomBytes } from 'node:crypto';

import { createObservedEvent } from '@itw-conformance-tool/conformance';
import { toResult } from '@itw-conformance-tool/utils';
import {
  extractClientIdPrefix,
  parseAuthorizationResponse,
  type Openid4vpAuthorizationRequestPayload
} from '@pagopa/io-wallet-oid4vp';
import { decodeJwt } from 'jose';
import z from 'zod';

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
  state: z.string().optional().describe('Wallet session state identifier.')
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

function readField(source: unknown, key: string): unknown {
  return typeof source === 'object' && source !== null ? (source as Record<string, unknown>)[key] : undefined;
}

// Collects the credential query identifiers declared in the Request Object's
// DCQL query so a test can assert one vp_token entry exists per requested
// credential (WP_093).
function extractRequestedCredentialIds(dcqlQuery: unknown): string[] {
  const credentials = readField(dcqlQuery, 'credentials');
  if (!Array.isArray(credentials)) return [];

  return credentials.flatMap((credential) => {
    const id = readField(credential, 'id');
    return typeof id === 'string' ? [id] : [];
  });
}

export const getAuthorizationResponseHandler = async (
  req: FastifyRequest<{
    Body: AuthorizationResponsePayload;
    Querystring: SessionIdQuerystring;
  }>,
  reply: FastifyReply
): Promise<FastifyReply> => {
  const requestObjectRepository = req.server.repository.requestObject;
  const authorizationRequest = requestObjectRepository.getBySessionId(req.query.session_id);

  // WP_091 / WP_092: the wallet posts the encrypted Authorization Response to the
  // response_uri. Correlation is disabled, so the event is emitted uncorrelated;
  // the raw JWE is forwarded so tests can assert the POST method and inspect the
  // JWE protected header (readable without the decryption key).
  await req.server.conformanceEventSink.emit(
    createObservedEvent({
      name: 'rp.presentation_response.received',
      correlationId: null,
      service: 'relying-party',
      requestId: req.id,
      diagnostic: {
        endpoint: '/auth/response',
        method: req.method,
        outcome: 'error' in req.body ? 'error' : 'response',
        response: 'response' in req.body ? req.body.response : undefined,
        state: req.body.state ?? null
      }
    })
  );

  if ('error' in req.body) {
    // WP_090: the wallet rejected the Request Object and reported the failure to
    // the response_uri as an Authorization Error Response. Emitted as its own
    // event so a negative scenario can require the error report without also
    // accepting a completed presentation.
    await req.server.conformanceEventSink.emit(
      createObservedEvent({
        name: 'rp.presentation_error.received',
        correlationId: null,
        service: 'relying-party',
        requestId: req.id,
        diagnostic: {
          endpoint: '/auth/response',
          method: req.method,
          error: req.body.error,
          errorDescription: req.body.error_description ?? null,
          state: req.body.state ?? null
        }
      })
    );

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
    iacaX509: req.server.config.RP_X509,
    requestObject: authorizationRequestPayload,
    verifierEncryptionPublicJwk: req.server.jwks.enc.public
  });

  const verificationPromise = async () => ({
    vpToken: await verifier.verifyCredentials(),
    state: authResponseResult.value.authorizationResponsePayload.state !== authorizationRequestPayload.state
  });

  const verificationResult = await toResult(verificationPromise());
  if (!verificationResult.ok) {
    await req.server.conformanceEventSink.emit(
      createObservedEvent({
        name: 'vp_token.validation.failed',
        correlationId: null,
        service: 'relying-party',
        requestId: req.id,
        validation: { reason: verificationResult.error.message }
      })
    );

    requestObjectRepository.update(authorizationRequest.id, 'rejected');
    req.log.error({ error: verificationResult.error }, 'Error verifying credentials');
    return reply.status(403).send({ error: 'invalid_request', error_description: verificationResult.error.message });
  }

  // WP_093 / WP_093a / WP_093b / WP_093c: forward the decrypted Authorization
  // Response evidence — the echoed state, the vp_token structure and the raw
  // SD-JWT presentations — so tests can assert the vp_token shape, SD-JWT
  // disclosures and KB-JWT format by decoding the tokens themselves.
  const authorizationResponsePayload = authResponseResult.value.authorizationResponsePayload;
  const vpToken = authorizationResponsePayload.vp_token;
  const { clientId } = extractClientIdPrefix(authorizationRequestPayload.client_id);

  // The path is exactly the attested `redirect_uris` entry; the session is
  // identified by query parameters alone. OpenID4VP requires the returned
  // `redirect_uri` to carry the `response_code`, so a wallet has to compare the
  // base URI and ignore the query — putting the state in the path instead would
  // make a nominal redirect fail that comparison (WP_094 / WP_094a).
  const redirectUri = new URL(`${req.server.config.BASE_URL}/callback`);
  const responseCode = randomBytes(32).toString('hex');
  redirectUri.searchParams.set('state', authorizationRequest.id);
  redirectUri.searchParams.set('response_code', responseCode);

  await req.server.conformanceEventSink.emit(
    createObservedEvent({
      name: 'vp_token.validation.succeeded',
      correlationId: null,
      service: 'relying-party',
      requestId: req.id,
      diagnostic: {
        endpoint: '/auth/response',
        state: readField(authorizationResponsePayload, 'state') ?? null,
        requestObjectState: authorizationRequestPayload.state ?? null,
        requestedCredentialIds: extractRequestedCredentialIds(authorizationRequestPayload.dcql_query),
        vpTokenCredentialIds: Object.keys(vpToken as Record<string, unknown>),
        nonce: authorizationRequestPayload.nonce ?? null,
        clientId,
        // WP_094 / WP_094a: the redirect_uri handed back to the wallet, so a test
        // can check it against the redirect_uris the Relying Party attested.
        redirectUri: redirectUri.toString(),
        vpToken
      }
    })
  );

  requestObjectRepository.update(
    authorizationRequest.id,
    'verified',
    redirectUri.toString(),
    verificationResult.value.vpToken
  );

  return reply.status(200).send({ redirect_uri: redirectUri.toString() });
};
