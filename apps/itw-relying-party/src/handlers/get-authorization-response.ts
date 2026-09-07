import { randomBytes } from 'node:crypto';

import { createObservedEvent } from '@itw-conformance-tool/conformance';
import { toResult } from '@itw-conformance-tool/utils';
import {
  JarmMode,
  parseAuthorizationResponse,
  type Openid4vpAuthorizationRequestPayload
} from '@pagopa/io-wallet-oid4vp';
import { decodeJwt } from 'jose';
import z from 'zod';

import { REDIRECT_URI_PATH } from '../domain/verifier-metadata.js';
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

/**
 * Acknowledgement body. `redirect_uri` is present only for the Same Device
 * flow; a Cross Device presentation and an Authorization Error Response are
 * both acknowledged with an empty JSON object.
 */
export const authorizationResponseResultSchema = z.object({
  redirect_uri: z
    .url()
    .optional()
    .describe('Absolute browser redirect URI to continue the relying-party flow; same-device only.')
});

export const authorizationResponseErrorSchema = z.object({
  error: z.string().describe('OpenID4VP error code.'),
  error_description: z.string().optional().describe('Human-readable error details.')
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
    // A response endpoint that has successfully processed an Authorization
    // Error Response must acknowledge it exactly as it would a successful one:
    // 200 with a JSON object body. An empty body would leave a wallet unable to
    // tell acknowledgement from a truncated response.
    return reply.status(200).header('cache-control', 'no-store').send({});
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

  // IT Wallet 1.4 raises the Authorization Response from SHOULD to MUST be
  // encrypted: `direct_post.jwt` has to use ECDH-ES key agreement on P-256 with
  // AES-GCM content encryption. The SDK does not enforce it — its JARM verifier
  // rejects only a response that is neither signed nor encrypted, so a
  // signed-only one would otherwise be accepted here — but it does report the
  // mode it detected, which is what this checks.
  const jarmMode = authResponseResult.value.jarm?.type;
  if (jarmMode !== JarmMode.Encrypted && jarmMode !== JarmMode.SignedEncrypted) {
    const reason = `Authorization Response must be encrypted, got ${jarmMode ?? 'an unencrypted response'}`;

    await req.server.conformanceEventSink.emit(
      createObservedEvent({
        name: 'vp_token.validation.failed',
        correlationId: null,
        service: 'relying-party',
        requestId: req.id,
        validation: { reason }
      })
    );

    requestObjectRepository.update(authorizationRequest.id, 'rejected');
    req.log.error({ jarmMode }, 'Authorization response is not encrypted');
    return reply.status(400).send({ error: 'invalid_request', error_description: reason });
  }

  const verifier = new VpTokenVerifier({
    authResponse: authResponseResult.value,
    iacaX509: req.server.config.RP_X509,
    relyingPartyEntityId: req.server.config.BASE_URL,
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
  // The Relying Party entity identifier. It can no longer be recovered from
  // `client_id`, which under the `x509_hash` prefix is a certificate hash.
  const clientId = req.server.config.BASE_URL;

  // The path is exactly the attested `redirect_uris` entry; the session is
  // identified by query parameters alone. OpenID4VP requires the returned
  // `redirect_uri` to carry the `response_code`, so a wallet has to compare the
  // base URI and ignore the query — putting the state in the path instead would
  // make a nominal redirect fail that comparison (WP_094 / WP_094a).
  const redirectUri = new URL(`${req.server.config.BASE_URL}${REDIRECT_URI_PATH}`);
  const responseCode = randomBytes(32).toString('hex');
  redirectUri.searchParams.set('state', authorizationRequest.id);
  redirectUri.searchParams.set('response_code', responseCode);

  // A returned `redirect_uri` is an instruction to send the user-agent there,
  // and only the Same Device flow has a user-agent on the wallet's device to
  // send. In Cross Device the browser that started the flow is elsewhere and
  // reaches the same destination by polling /status, so handing the wallet a
  // redirect it cannot meaningfully follow would be an invitation to misbehave.
  // It is still generated and stored either way: /status and /callback both
  // resolve the session through the response_code embedded here.
  const isSameDeviceFlow = authorizationRequest.flowType === 'same-device';

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
        // `clientId` is the Relying Party entity identifier — the value IT
        // Wallet requires the key binding `aud` to carry. `clientIdPrefixed` is
        // what the Request Object actually advertised, which OpenID4VP 1.0
        // requires instead; both are accepted, and the form each presentation
        // used is reported alongside (WP_093c).
        clientId,
        clientIdPrefixed: authorizationRequestPayload.client_id,
        acceptedKeyBindingAudiences: verifier.acceptedKeyBindingAudiences,
        keyBindingAudiences: verifier.keyBindingAudiences,
        // WP_094 / WP_094a: the redirect_uri handed back to the wallet, so a test
        // can check it against the redirect_uris the Relying Party attested.
        // `redirectUriReturned` records whether it was actually sent: only the
        // Same Device flow receives one.
        redirectUri: redirectUri.toString(),
        redirectUriReturned: isSameDeviceFlow,
        flowType: authorizationRequest.flowType,
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

  return reply
    .status(200)
    .header('cache-control', 'no-store')
    .send(isSameDeviceFlow ? { redirect_uri: redirectUri.toString() } : {});
};
