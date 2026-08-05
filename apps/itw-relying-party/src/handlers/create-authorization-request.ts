import { randomBytes, randomUUID } from 'node:crypto';

import {
  createAuthorizationRequest,
  createX509HashClientId,
  type Openid4vpAuthorizationRequestPayload
} from '@pagopa/io-wallet-oid4vp';
import { DcqlQuery, getDcqlErrorFromUnknown } from 'dcql';
import z from 'zod';

import { buildRelyingPartyEntityConfiguration, findEntityConfigurationFault } from '../domain/entity-configuration.js';
import { buildRelyingPartyTrustChain } from '../domain/trust-chain.js';
import { buildRequestObjectClientMetadata, REQUEST_URI_PATH, RESPONSE_URI_PATH } from '../domain/verifier-metadata.js';
import { toFederationClientId } from '../utils/request-object.js';

import type { JwtSignerFederation, JwtSignerX5c, TrustChain } from '@pagopa/io-wallet-oauth2';
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
  include_trust_chain: z
    .boolean()
    .default(false)
    .describe(
      'Inline the federation Trust Chain in the Request Object header. Only meaningful with `openid_federation`, where it hands the wallet the Relying Party Entity Configuration, the Trust Anchor Subordinate Statement about it and the Trust Anchor Entity Configuration, so the Trust Chain needs no resolution over the network. Ignored under `x509_hash`, whose header commits to the certificate chain instead.'
    ),
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
  const { RP_X509, BASE_URL, TRUST_ANCHOR_URL } = req.server.config;
  const requestObjectRepository = req.server.repository.requestObject;
  const nonceRepository = req.server.repository.nonce;

  const { client_id_prefix, dcqlQuery, flow_type, include_trust_chain, request_uri_method, wallet_auth_base_uri } =
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

  const isFederationPrefix = client_id_prefix === 'openid_federation';

  // OpenID4VP requires the engagement `client_id` to be identical to the
  // Request Object `client_id` claim, including the Client Identifier Prefix, so
  // a single value serves both. The `x509_hash` identifier hashes the very
  // certificate published as `x5c` below, so a wallet resolving that prefix
  // finds the two agree; `openid_federation` carries the entity identifier
  // instead, which is what points the wallet at the Trust Chain.
  const clientId = isFederationPrefix
    ? toFederationClientId(BASE_URL)
    : await createX509HashClientId({
        hash: req.server.callbacks.hash,
        certificateChain: [RP_X509]
      });

  // The Trust Chain the wallet would otherwise resolve for itself, handed to it
  // in the JAR header instead. It is only meaningful behind the federation
  // prefix: under `x509_hash` the wallet establishes trust through the
  // certificate chain and never consults the federation, so a Trust Chain there
  // would attest something the wallet is not asked to read.
  //
  // The Relying Party Entity Configuration is signed here rather than fetched:
  // it is the same artifact `/.well-known/openid-federation` would serve, active
  // Entity-Configuration fault included, so what the wallet finds inlined and
  // what it would find by fetching cannot disagree.
  let trustChain: TrustChain | undefined;

  if (isFederationPrefix && include_trust_chain) {
    try {
      trustChain = await buildRelyingPartyTrustChain({
        entityConfigurationJwt: await buildRelyingPartyEntityConfiguration({
          baseUrl: BASE_URL,
          encryptionJwk: req.server.jwks.enc.public,
          faultType: findEntityConfigurationFault(req.server.rpFaultStore.getActive())?.type,
          federationPrivateJwk: req.server.jwks.federation.private,
          federationPublicJwk: req.server.jwks.federation.public,
          signingJwk: req.server.jwks.sig.public,
          trustAnchorUrl: TRUST_ANCHOR_URL
        }),
        relyingPartyEntityId: BASE_URL,
        trustAnchorUrl: TRUST_ANCHOR_URL
      });
    } catch (error) {
      // An engagement that promises an inlined Trust Chain and carries a partial
      // one would put the wallet in front of a defect no scenario asked for, so
      // the engagement is refused instead.
      req.log.error({ err: error }, 'Trust Chain assembly failed');
      return reply.badGateway(
        `Unable to assemble the Relying Party Trust Chain from ${TRUST_ANCHOR_URL}: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  // The signer decides how a wallet resolves the key, so it is chosen with the
  // prefix — the SDK rejects the two disagreeing. Without an inlined
  // `trust_chain` the federation signer offers no alternative key source at all:
  // no `x5c` either, leaving `kid` as the only handle on the signing key
  // (WP_084). IT Wallet 1.4 makes `x5c` optional precisely so the JAR header can
  // take that shape.
  const jwtSigner: JwtSignerFederation | JwtSignerX5c = isFederationPrefix
    ? { alg: 'ES256', kid: req.server.jwks.sig.public.kid, method: 'federation', ...(trustChain ? { trustChain } : {}) }
    : { alg: 'ES256', kid: req.server.jwks.sig.public.kid, method: 'x5c', x5c: [RP_X509] };

  const payload: Openid4vpAuthorizationRequestPayload = {
    client_id: clientId,
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
      jwtSigner
    }
  });

  // Stored in the shape the wallet will be served: the retrieval handler reuses
  // this header verbatim, so the key resolution path the engagement announces is
  // decided here, once, and cannot drift from the `client_id` it carries.
  requestObjectRepository.insert({
    flowType: flow_type,
    id: state,
    jwt: jar.authorizationRequestJwt,
    sessionId
  });

  const requestUri = `${BASE_URL}${REQUEST_URI_PATH}/${state}`;
  // `request_uri_method` is only advertised when the
  // caller asked for a specific retrieval method, leaving the default (`get`,
  // WP_082) implicit as before.
  const presentationParams = new URLSearchParams({
    client_id: clientId,
    request_uri: requestUri,
    ...(request_uri_method ? { request_uri_method } : {})
  });

  const baseUrl = new URL(wallet_auth_base_uri);
  for (const [key, value] of presentationParams) {
    baseUrl.searchParams.set(key, value);
  }

  return reply.status(200).send({
    url: baseUrl.toString()
  } satisfies CreateAuthorizationRequestResponse);
};
