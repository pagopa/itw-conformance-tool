import { randomBytes, randomUUID } from 'node:crypto';

import { createAuthorizationRequest, type Openid4vpAuthorizationRequestPayload } from '@pagopa/io-wallet-oid4vp';
import { DcqlQuery, getDcqlErrorFromUnknown } from 'dcql';
import z from 'zod';

import { USER_AGENT_SESSION_COOKIE, userAgentSessionCookieOptions } from '../domain/user-agent-session.js';
import { buildRequestObjectClientMetadata, REQUEST_URI_PATH, RESPONSE_URI_PATH } from '../domain/verifier-metadata.js';
import { resolveClientId, toFederationRequestObjectJwt, toX509HashClientId } from '../utils/request-object.js';

import type { FastifyReply, FastifyRequest } from 'fastify';

export const createAuthorizationRequestPayloadSchema = z.object({
  client_id_prefix: z
    .enum(['openid_federation', 'x509_hash'])
    .default('x509_hash')
    .describe(
      'Client Identifier Prefix the engagement and the Request Object carry. `x509_hash` (the default) makes the wallet verify the Request Object with the x5c certificate chain and read the Verifier metadata from client_metadata; `openid_federation` makes it resolve both through the federation Trust Chain.'
    ),
  dcqlQuery: z
    .object({
      credential_sets: z
        .array(
          z.object({
            options: z.array(z.array(z.string())).describe('Credential identifiers accepted as alternatives.'),
            purpose: z.union([z.string(), z.number(), z.record(z.string(), z.any())]).optional(),
            required: z.boolean().optional()
          })
        )
        .optional(),
      credentials: z.array(
        z.discriminatedUnion('format', [
          z.object({
            claim_sets: z.array(z.array(z.string())).optional(),
            claims: z
              .array(
                z.object({
                  id: z.string().optional(),
                  path: z.array(z.union([z.string(), z.number(), z.null()])),
                  values: z.array(z.union([z.string(), z.number(), z.boolean()])).optional()
                })
              )
              .optional(),
            format: z.literal('dc+sd-jwt').describe('Credential format requested from the wallet.'),
            id: z.string().describe('Credential query identifier.'),
            meta: z.object({ vct_values: z.array(z.string()).optional() }).optional()
          }),
          z.object({
            claim_sets: z.array(z.array(z.string())).optional(),
            claims: z
              .array(
                z.union([
                  z.object({
                    claim_name: z.string(),
                    id: z.string().optional(),
                    namespace: z.string(),
                    values: z.array(z.union([z.string(), z.number(), z.boolean()])).optional()
                  }),
                  z.object({
                    id: z.string().optional(),
                    intent_to_retain: z.boolean().optional(),
                    path: z.tuple([z.string(), z.string()]),
                    values: z.array(z.union([z.string(), z.number(), z.boolean()])).optional()
                  })
                ])
              )
              .optional(),
            format: z.literal('mso_mdoc').describe('Credential format requested from the wallet.'),
            id: z.string().describe('Credential query identifier.'),
            meta: z.object({ doctype_value: z.string().optional() }).optional()
          })
        ])
      )
    })
    .describe('DCQL query describing the verifiable presentations required by the relying party.'),
  flow_type: z.enum(['same-device', 'cross-device']).describe('Presentation flow type expected by the relying party.'),
  request_uri_method: z
    .enum(['get', 'post'])
    .optional()
    .describe('Retrieval method advertised for the request_uri; omitted from the engagement URL when not set.'),
  wallet_auth_base_uri: z
    .url()
    .trim()
    .min(1)
    .default('openid4vp://')
    .describe(
      'Wallet authorization endpoint used to launch the presentation flow. Defaults to the OpenID4VP custom scheme; pass a wallet-specific scheme or universal link to engage a particular Wallet Solution.'
    )
});

export type CreateAuthorizationRequestPayload = z.infer<typeof createAuthorizationRequestPayloadSchema>;

export const createAuthorizationRequestResponseSchema = z.object({
  url: z.url().describe('Wallet URL containing the request_uri, client_id, and state query parameters.')
});

export type CreateAuthorizationRequestResponse = z.infer<typeof createAuthorizationRequestResponseSchema>;

export const createAuthorizationRequestHandler = async (
  req: FastifyRequest<{ Body: CreateAuthorizationRequestPayload }>,
  reply: FastifyReply
): Promise<FastifyReply> => {
  const { IACA_X509, BASE_URL } = req.server.config;
  const requestObjectRepository = req.server.repository.requestObject;
  const nonceRepository = req.server.repository.nonce;

  const { client_id_prefix, dcqlQuery, flow_type, request_uri_method, wallet_auth_base_uri } =
    createAuthorizationRequestPayloadSchema.parse(req.body);

  let parsedQuery: DcqlQuery.Output;

  try {
    parsedQuery = DcqlQuery.parse(dcqlQuery as DcqlQuery.Input);
    DcqlQuery.validate(parsedQuery);
  } catch (error) {
    const { code, cause, message } = getDcqlErrorFromUnknown(error);
    return reply.badRequest().send({
      error: {
        code,
        cause,
        message
      }
    });
  }

  const nonce = randomBytes(32).toString('hex');
  nonceRepository.insert(nonce);

  const state = randomUUID();
  const sessionId = randomUUID();
  // IT Wallet 1.4 binds `state` to the user-agent session that started the flow
  // and accepts the Same Device redirect back only within it. The identifier is
  // opaque and travels to the browser in a cookie; `/callback` compares the two.
  const userAgentSessionId = randomUUID();

  // The `x509_hash` identifier hashes the very certificate published as `x5c`
  // below, so a wallet resolving that prefix finds the two agree. The SDK's JAR
  // header schema demands `x5c` at IT Wallet 1.4 just as it did at 1.3 (1.4
  // reuses the same schema), so the Request Object is always built in that shape
  // and rewritten afterwards when the scenario asked for the federation one —
  // where 1.4 makes `x5c` optional.
  const nominalClientId = toX509HashClientId(IACA_X509);

  const payload: Openid4vpAuthorizationRequestPayload = {
    client_id: nominalClientId,
    client_metadata: buildRequestObjectClientMetadata({
      baseUrl: BASE_URL,
      encryptionJwk: req.server.jwks.enc.public
    }),
    dcql_query: dcqlQuery,
    iss: BASE_URL,
    nonce,
    response_mode: 'direct_post.jwt',
    response_type: 'vp_token',
    response_uri: `${BASE_URL}${RESPONSE_URI_PATH}?session_id=${sessionId}`,
    state
  };

  const { jar } = await createAuthorizationRequest({
    authorizationRequestPayload: payload,
    callbacks: {
      encryptJwe: req.server.callbacks.encryptJwe,
      signJwt: req.server.callbacks.signJwt
    },
    config: req.server.sdkConfig,
    jar: {
      expiresInSeconds: 10000,
      jwtSigner: {
        alg: 'ES256',
        kid: req.server.jwks.sig.public.kid,
        method: 'x5c',
        x5c: [IACA_X509]
      }
    }
  });

  // Stored in the shape the wallet will be served: the retrieval handler reuses
  // this header verbatim, so the key resolution path the engagement announces is
  // decided here, once, and cannot drift from the `client_id` below.
  const requestObjectJwt =
    client_id_prefix === 'openid_federation'
      ? await toFederationRequestObjectJwt({
          jwt: jar.authorizationRequestJwt,
          relyingPartyEntityId: BASE_URL,
          signingPrivateJwk: req.server.jwks.sig.private
        })
      : jar.authorizationRequestJwt;

  requestObjectRepository.insert({
    flowType: flow_type,
    id: state,
    jwt: requestObjectJwt,
    sessionId,
    userAgentSessionId
  });

  const requestUri = `${BASE_URL}${REQUEST_URI_PATH}/${state}`;
  // OpenID4VP requires the engagement `client_id` to be identical to the
  // Request Object `client_id` claim, including the Client Identifier Prefix.
  const engagementClientId = resolveClientId(nominalClientId, BASE_URL, client_id_prefix);
  // `request_uri_method` is only advertised when the
  // caller asked for a specific retrieval method, leaving the default (`get`,
  // WP_082) implicit as before.
  const presentationParams = new URLSearchParams({
    client_id: engagementClientId,
    request_uri: requestUri,
    ...(request_uri_method ? { request_uri_method } : {})
  });

  const baseUrl = new URL(wallet_auth_base_uri);
  for (const [key, value] of presentationParams) {
    baseUrl.searchParams.set(key, value);
  }

  return reply
    .setCookie(USER_AGENT_SESSION_COOKIE, userAgentSessionId, userAgentSessionCookieOptions)
    .status(200)
    .send({
      url: baseUrl.toString()
    } satisfies CreateAuthorizationRequestResponse);
};
