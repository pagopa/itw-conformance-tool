import { createObservedEvent } from '@itw-conformance-tool/conformance';
import {
  createItWalletEntityConfiguration,
  itWalletMetadataV1_4,
  type ItWalletEntityConfigurationClaimsOptions
} from '@pagopa/io-wallet-oid-federation';
import { ValidationError } from '@pagopa/io-wallet-utils';

import { signJwtCallback } from '../federation/signer.js';

import type { WalletProviderPublicJwk, WalletProviderSigningJwk } from '../plugins/keys.js';
import type { FastifyPluginAsync } from 'fastify';

const ENTITY_STATEMENT_TTL_SECONDS = 3600;
function toSigningJwk(
  privateJwk: WalletProviderSigningJwk,
  publicJwk: WalletProviderPublicJwk
): WalletProviderSigningJwk {
  return { ...privateJwk, kid: publicJwk.kid, kty: publicJwk.kty };
}

const federationRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/.well-known/openid-federation',
    method: 'GET',
    schema: {
      tags: ['Federation']
    },
    handler: async (request, reply) => {
      try {
        const { baseUrl, trustAnchorEntityId, walletName } = app.config;
        const { signingPrivateJwk, signingPublicJwk } = app.walletProviderKeys;
        const iat = Math.floor(Date.now() / 1000);
        const metadata = {
          wallet_solution: {
            jwks: { keys: [signingPublicJwk] },
            logo_uri: 'https://io.italia.it/assets/img/io-it-logo-blue.svg',
            wallet_metadata: {
              wallet_name: walletName,
              authorization_endpoint: `${baseUrl}/wallet/authorize`,
              credential_offer_endpoint: `${baseUrl}/wallet/credential-offer`,
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
            authority_hints: [trustAnchorEntityId],
            exp: iat + ENTITY_STATEMENT_TTL_SECONDS,
            iat,
            iss: baseUrl,
            jwks: { keys: [signingPublicJwk] },
            metadata: parsedMetadata.data as ItWalletEntityConfigurationClaimsOptions['metadata'],
            sub: baseUrl
          },
          header: {
            alg: 'ES256',
            kid: signingPublicJwk.kid,
            typ: 'entity-statement+jwt'
          },
          signJwtCallback: async ({ toBeSigned }) =>
            signJwtCallback({ jwk: toSigningJwk(signingPrivateJwk, signingPublicJwk), toBeSigned })
        });

        await app.conformanceEventSink?.emit(
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
    }
  });
};

export default federationRoute;
