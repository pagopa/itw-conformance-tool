import { createObservedEvent } from '@itw-conformance-tool/conformance';
import { isInternalServiceRequest } from '@itw-conformance-tool/utils';

import { createSubordinate } from '../federation/statements.js';

import type { JsonWebKey, MetadataPolicyOperator } from '@pagopa/io-wallet-oid-federation';
import type { FastifyPluginAsync, FastifyRequest } from 'fastify';

interface FetchQuerystring {
  sub: string;
}

const fetchRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/fetch',
    method: 'GET',
    schema: {
      tags: ['Federation'],
      // Rejects a missing/empty `sub` as a client error before any signing logic runs.
      querystring: {
        type: 'object',
        required: ['sub'],
        properties: {
          sub: { type: 'string', minLength: 1 }
        }
      }
    },
    handler: async (request: FastifyRequest<{ Querystring: FetchQuerystring }>, reply) => {
      const { sub } = request.query;
      const { baseUrl, issuerEntityId, rpEntityId, walletProviderEntityId } = app.config;

      // Already carrying its `kid` and its certifying `x5c`, as the `keys`
      // plugin derived it at startup.
      let subjectPublicJwk: JsonWebKey;
      let metadataPolicy: Record<string, Record<string, MetadataPolicyOperator>> | undefined;

      if (sub === issuerEntityId) {
        subjectPublicJwk = app.trustAnchorKeys.subordinatePublicJwks.issuer;
        metadataPolicy = {
          openid_credential_issuer: {
            credential_configurations_supported: {
              subset_of: [
                'dc_sd_jwt_EuropeanDisabilityCard',
                'dc_sd_jwt_PersonIdentificationData',
                'mso_mdoc_mDL',
                'org.iso.18013.5.1.mDL'
              ],
              essential: true
            }
          }
        };
      } else if (sub === rpEntityId) {
        subjectPublicJwk = app.trustAnchorKeys.subordinatePublicJwks.rp;
      } else if (sub === walletProviderEntityId) {
        subjectPublicJwk = app.trustAnchorKeys.subordinatePublicJwks.walletProvider;
      } else {
        return reply.code(404).send({ error: 'not_found' });
      }

      try {
        const subordinateStatement = await createSubordinate({
          federationCertificateChain: app.trustAnchorKeys.federationCertificateChain,
          federationPrivateJwk: app.trustAnchorKeys.federationPrivateJwk,
          subjectEntityId: sub,
          subjectPublicJwk,
          trustAnchorBaseUrl: baseUrl,
          metadataPolicy
        });

        // Only a wallet resolving the Trust Chain is evidence of Trust Chain
        // resolution. The Relying Party fetches the very same statement to
        // inline it in a Request Object header, and adopting that call as
        // evidence would credit the wallet with a step it never took.
        if (!isInternalServiceRequest(request.headers)) {
          await app.conformanceEventSink?.emit(
            createObservedEvent({
              name: 'federation.fetch.requested',
              correlationId: request.conformance?.correlation?.correlationId ?? null,
              service: 'federation',
              requestId: request.id,
              diagnostic: {
                endpoint: '/fetch',
                sub
              }
            })
          );
        }

        return reply.code(200).header('Content-Type', 'application/entity-statement+jwt').send(subordinateStatement);
      } catch (error) {
        request.log.error({ err: error }, 'Subordinate statement generation failed');
        return reply.code(500).send({ error: 'internal_server_error' });
      }
    }
  });
};

export default fetchRoute;
