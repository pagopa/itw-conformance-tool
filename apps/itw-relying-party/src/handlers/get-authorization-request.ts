import { createObservedEvent } from '@itw-conformance-tool/conformance';
import z from 'zod';

import { emitRpFaultApplied } from '../faults/rp-fault-evidence.js';
import {
  describeFederationKeyRequestObject,
  reissueRequestObjectJwt,
  type RequestObjectMutation
} from '../utils/request-object.js';

import type { ActiveRpFault } from '../faults/rp-fault-store.js';
import type { FastifyReply, FastifyRequest } from 'fastify';

export const getAuthorizationRequestParamsSchema = z.object({
  state: z.uuid().describe('Authorization request state identifier.')
});

export type GetAuthorizationRequestParams = z.infer<typeof getAuthorizationRequestParamsSchema>;

/**
 * `request_uri_method=post` body. Both members are optional on the wire:
 * `wallet_metadata` is OPTIONAL and `wallet_nonce` is RECOMMENDED, so a wallet
 * that omits either still receives a Request Object instead of a 4xx that would
 * hide the retrieval evidence.
 */
export const postAuthorizationRequestBodySchema = z.object({
  wallet_metadata: z.string().optional().describe('JSON object carrying the Wallet Instance metadata parameters.'),
  wallet_nonce: z.string().optional().describe('Wallet-generated nonce the Request Object must echo back.')
});

export type PostAuthorizationRequestBody = z.infer<typeof postAuthorizationRequestBodySchema>;

export const getAuthorizationRequestResponseSchema = z.string().describe('Signed authorization request JWT.');

/**
 * Maps an active Relying Party fault profile onto the mutation the served
 * Request Object must carry. Profiles applied elsewhere in the flow (Entity
 * Configuration, Authorization Response) leave the Request Object nominal.
 */
function resolveRequestObjectMutation(
  fault: ActiveRpFault | undefined
): { fault: ActiveRpFault; mutation: RequestObjectMutation } | undefined {
  if (!fault) return undefined;

  switch (fault.profile.type) {
    case 'request-object-invalid-signature':
      return { fault, mutation: { type: 'invalid-signature' } };
    case 'request-object-invalid-client-id':
      return { fault, mutation: { type: 'mismatched-issuer' } };
    case 'request-object-federation-key':
      return { fault, mutation: { type: 'federation-key' } };
    case 'request-object-missing-parameter':
      return { fault, mutation: { type: 'omit-parameter', parameter: fault.profile.parameter } };
    default:
      return undefined;
  }
}

/**
 * Parses the `wallet_metadata` form field, which travels as a JSON string
 * inside an `application/x-www-form-urlencoded` body. Malformed JSON is
 * reported as such rather than thrown, so the Request Object is still served
 * and the defect remains visible as evidence.
 */
function parseWalletMetadata(value: string | undefined): { parsed: unknown; wellFormed: boolean } {
  if (value === undefined) return { parsed: null, wellFormed: false };

  try {
    return { parsed: JSON.parse(value) as unknown, wellFormed: true };
  } catch {
    return { parsed: null, wellFormed: false };
  }
}

/**
 * Serves the signed Request Object referenced by the engagement `request_uri`,
 * over HTTP GET (WP_082) or over HTTP POST carrying `wallet_metadata` and
 * `wallet_nonce` (WP_083, WP_083a/b/c).
 *
 * The stored Request Object is served verbatim unless this retrieval has to
 * change it: a POST that provided `wallet_nonce` must get it echoed back (it is
 * REQUIRED in the Request Object once the wallet provided it), and an active
 * Relying Party fault must be applied to what the wallet actually receives.
 */
export const getAuthorizationRequestHandler = async (
  req: FastifyRequest<{ Body?: PostAuthorizationRequestBody; Params: GetAuthorizationRequestParams }>,
  reply: FastifyReply
): Promise<FastifyReply> => {
  const requestObjectRepository = req.server.repository.requestObject;
  const state = req.params.state;
  const requestObject = requestObjectRepository.get(state);

  const isPostRetrieval = req.method === 'POST';
  const walletNonce = isPostRetrieval ? req.body?.wallet_nonce : undefined;
  const walletMetadata = isPostRetrieval ? parseWalletMetadata(req.body?.wallet_metadata) : undefined;

  const activeFault = resolveRequestObjectMutation(req.server.rpFaultStore.getActive());

  const jwt =
    activeFault || walletNonce !== undefined
      ? await reissueRequestObjectJwt({
          jwt: requestObject.jwt,
          mutation: activeFault?.mutation,
          signingPrivateJwk: req.server.jwks.sig.private,
          walletNonce
        })
      : requestObject.jwt;

  // WP_082 / WP_083: the wallet retrieves the signed Request Object from the
  // request_uri endpoint. Correlation is disabled, so the event is emitted
  // uncorrelated and the scenario adopts it as post-start evidence narrowed by
  // the endpoint/method diagnostics. The POST body is forwarded so tests can
  // assert the wallet_metadata schema (WP_083a), the absence of personal data
  // in it (WP_083b), and the freshly generated wallet_nonce (WP_083c).
  await req.server.conformanceEventSink.emit(
    createObservedEvent({
      name: 'rp.request_object.requested',
      correlationId: null,
      service: 'relying-party',
      requestId: req.id,
      diagnostic: {
        endpoint: '/auth/request/:state',
        method: req.method,
        contentType: isPostRetrieval ? (req.headers['content-type'] ?? null) : null,
        walletMetadata: walletMetadata?.parsed ?? null,
        walletMetadataWellFormed: walletMetadata?.wellFormed ?? null,
        walletNonce: walletNonce ?? null,
        walletNonceEchoed: walletNonce !== undefined
      }
    })
  );

  if (activeFault) {
    // Emission failures must not be reported as a successfully applied fault:
    // any error here propagates instead of emitting a false "applied" event.
    await emitRpFaultApplied(req, {
      artifact: jwt,
      endpoint: '/auth/request/:state',
      fault: activeFault.fault,
      diagnostic: {
        method: req.method,
        ...(activeFault.mutation.type === 'omit-parameter'
          ? { omittedParameter: activeFault.mutation.parameter }
          : activeFault.mutation.type === 'mismatched-issuer'
            ? { mutatedClaim: 'iss' }
            : activeFault.mutation.type === 'federation-key'
              ? // WP_084: proves what the wallet was handed — no `x5c` to verify
                // with, and the `kid` it must look up in
                // `metadata.openid_credential_verifier.jwks`.
                { keyResolution: 'federation', ...describeFederationKeyRequestObject(jwt) }
              : { mutatedArtifactPart: 'signature' })
      }
    });
  }

  requestObjectRepository.update(state, 'checking');
  return reply.code(200).header('content-type', 'application/oauth-authz-req+jwt').send(jwt);
};
