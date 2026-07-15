import { randomBytes, randomUUID } from 'node:crypto';

import { createAuthorizationRequest, type Openid4vpAuthorizationRequestPayload } from '@pagopa/io-wallet-oid4vp';
import { DcqlQuery, getDcqlErrorFromUnknown } from 'dcql';
import z from 'zod';

import type { FastifyReply, FastifyRequest } from 'fastify';

export const createAuthorizationRequestPayloadSchema = z.object({
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
        z.object({
          claim_sets: z.array(z.array(z.string())).optional(),
          claims: z
            .array(
              z.object({
                id: z.string().optional(),
                path: z.array(z.string()).describe('Claim path within the credential.'),
                values: z.array(z.union([z.string(), z.number(), z.boolean()])).optional()
              })
            )
            .optional(),
          format: z.enum(['dc+sd-jwt', 'mso_mdoc']).describe('Credential format requested from the wallet.'),
          id: z.string().describe('Credential query identifier.'),
          meta: z
            .object({ vct_values: z.array(z.string()).optional(), doctype_value: z.string().optional() })
            .optional()
        })
      )
    })
    .describe('DCQL query describing the verifiable presentations required by the relying party.'),
  flow_type: z.enum(['same-device', 'cross-device']).describe('Presentation flow type expected by the relying party.'),
  wallet_auth_base_uri: z
    .url()
    .trim()
    .min(1)
    .default('https://continua.io.pagopa.it/itw/auth')
    .describe('Wallet authorization endpoint used to launch the presentation flow.')
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
  const { IACA_X509_BASE64, BASE_URL } = req.server.config;
  const requestObjectRepository = req.server.repository.requestObject;
  const nonceRepository = req.server.repository.nonce;

  const { dcqlQuery, flow_type, wallet_auth_base_uri } = createAuthorizationRequestPayloadSchema.parse(req.body);

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

  const payload: Openid4vpAuthorizationRequestPayload = {
    client_id: 'x509_hash:' + BASE_URL,
    client_metadata: {
      application_type: 'web',
      client_id: BASE_URL,
      client_name: 'IT Wallet Relying Party',
      encrypted_response_enc_values_supported: ['A256CBC-HS512'],
      jwks: {
        keys: [req.server.jwks.enc.public]
      },
      logo_uri: 'https://io.italia.it/assets/img/io-it-logo-blue.svg',
      request_uris: [`${BASE_URL}/auth/request`],
      response_uris: [`${BASE_URL}/auth/response`],
      vp_formats_supported: {
        'dc+sd-jwt': {
          'kb-jwt_alg_values': ['ES256'],
          'sd-jwt_alg_values': ['ES256', 'ES384']
        },
        mso_mdoc: {
          deviceauth_alg_values: [-9, -50],
          issuerauth_alg_values: [-9, -50]
        }
      }
    },
    dcql_query: dcqlQuery,
    iss: BASE_URL,
    nonce,
    response_mode: 'direct_post.jwt',
    response_type: 'vp_token',
    response_uri: `${BASE_URL}/auth/response?session_id=${sessionId}`,
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
        x5c: [IACA_X509_BASE64]
      }
    }
  });

  requestObjectRepository.insert({
    flowType: flow_type,
    id: state,
    jwt: jar.authorizationRequestJwt,
    sessionId
  });

  const requestUri = `${BASE_URL}/auth/request/${state}`;
  const presentationParams = new URLSearchParams({
    client_id: BASE_URL,
    request_uri: requestUri
  });

  const baseUrl = new URL(wallet_auth_base_uri);
  for (const [key, value] of presentationParams) {
    baseUrl.searchParams.set(key, value);
  }

  return reply.status(200).send({
    url: baseUrl.toString()
  } satisfies CreateAuthorizationRequestResponse);
};
