import { createObservedEvent } from '@itw-conformance-tool/conformance';
import {
  createItWalletEntityConfiguration,
  itWalletMetadataV1_4,
  type ItWalletEntityConfigurationClaimsOptions
} from '@pagopa/io-wallet-oid-federation';
import { ValidationError } from '@pagopa/io-wallet-utils';
import z from 'zod';

import { signJwtCallback } from '../utils/signer.js';

import type { FastifyReply, FastifyRequest } from 'fastify';

const ENTITY_STATEMENT_TTL_SECONDS = 3600;

export const entityConfigurationResponseSchema = z.string().describe('Signed OpenID Federation entity statement JWT.');

export const createEntityConfigurationHandler = async (
  request: FastifyRequest,
  reply: FastifyReply
): Promise<FastifyReply> => {
  try {
    const { BASE_URL, TRUST_ANCHOR_URL, WALLET_NAME } = request.server.config;
    const signingPrivateJwk = request.server.jwks.sig.private;
    const signingPublicJwk = request.server.jwks.sig.public;
    const iat = Math.floor(Date.now() / 1000);
    const metadata = {
      wallet_solution: {
        jwks: { keys: [signingPublicJwk] },
        logo_uri: 'https://io.italia.it/assets/img/io-it-logo-blue.svg',
        wallet_metadata: {
          wallet_name: WALLET_NAME,
          authorization_endpoint: `${BASE_URL}/wallet/authorize`,
          credential_offer_endpoint: `${BASE_URL}/wallet/credential-offer`,
          client_id_prefixes_supported: ['openid_federation'],
          request_object_signing_alg_values_supported: ['ES256'],
          response_types_supported: ['code'],
          vp_formats_supported: { 'dc+sd-jwt': {} }
        }
      }
    };

    const parsedMetadata = itWalletMetadataV1_4.safeParse(metadata);
    if (!parsedMetadata.success) {
      throw new ValidationError('Invalid Wallet Provider entity configuration metadata', parsedMetadata.error);
    }

    const entityConfiguration = await createItWalletEntityConfiguration({
      claims: {
        authority_hints: [TRUST_ANCHOR_URL],
        exp: iat + ENTITY_STATEMENT_TTL_SECONDS,
        iat,
        iss: BASE_URL,
        jwks: { keys: [signingPublicJwk] },
        metadata: parsedMetadata.data as ItWalletEntityConfigurationClaimsOptions['metadata'],
        sub: BASE_URL
      },
      header: {
        alg: 'ES256',
        kid: signingPublicJwk.kid,
        typ: 'entity-statement+jwt'
      },
      signJwtCallback: async ({ toBeSigned }) => signJwtCallback({ jwk: signingPrivateJwk, toBeSigned })
    });

    await request.server.conformanceEventSink.emit(
      createObservedEvent({
        name: 'wallet_provider.entity_configuration.requested',
        correlationId: request.conformance?.correlation?.correlationId ?? null,
        service: 'wallet-provider',
        requestId: request.id,
        diagnostic: { endpoint: '/.well-known/openid-federation' }
      })
    );

    return reply.code(200).header('Content-Type', 'application/entity-statement+jwt').send(entityConfiguration);
  } catch (error) {
    request.log.error({ err: error }, 'Wallet Provider entity configuration generation failed');
    return reply.code(500).send({ error: 'internal_server_error' });
  }
};
