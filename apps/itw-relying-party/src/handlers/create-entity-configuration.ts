import { createObservedEvent } from '@itw-conformance-tool/conformance';
import z from 'zod';

import { buildRelyingPartyEntityConfiguration, findEntityConfigurationFault } from '../domain/entity-configuration.js';
import { emitRpFaultApplied } from '../faults/rp-fault-evidence.js';

import type { FastifyReply, FastifyRequest } from 'fastify';

export const entityConfigurationResponseSchema = z.string().describe('Signed OpenID Federation entity statement JWT.');

export const createEntityConfigurationHandler = async (
  req: FastifyRequest,
  reply: FastifyReply
): Promise<FastifyReply> => {
  // The wallet fetches the RP Entity Configuration to discover its metadata and
  // verifier keys (WP_078 / WP_084). The request carries no scenario
  // correlation, so it is adopted as uncorrelated evidence narrowed by the
  // endpoint diagnostic.
  await req.server.conformanceEventSink.emit(
    createObservedEvent({
      name: 'rp.metadata.requested',
      correlationId: req.conformance?.correlation?.correlationId ?? null,
      service: 'relying-party',
      requestId: req.id,
      diagnostic: { endpoint: '/.well-known/openid-federation' }
    })
  );

  const { BASE_URL, TRUST_ANCHOR_URL } = req.server.config;
  const activeFault = findEntityConfigurationFault(req.server.rpFaultStore.getActive());

  const jwt = await buildRelyingPartyEntityConfiguration({
    baseUrl: BASE_URL,
    encryptionJwk: req.server.jwks.enc.public,
    faultType: activeFault?.type,
    federationPrivateJwk: req.server.jwks.federation.private,
    federationPublicJwk: req.server.jwks.federation.public,
    signingJwk: req.server.jwks.sig.public,
    trustAnchorUrl: TRUST_ANCHOR_URL
  });

  if (activeFault) {
    // Emission failures must not be reported as a successfully applied fault:
    // any error here propagates instead of emitting a false "applied" event.
    await emitRpFaultApplied(req, {
      artifact: jwt,
      endpoint: '/.well-known/openid-federation',
      fault: activeFault.fault
    });
  }

  return reply.code(200).header('Content-Type', 'application/entity-statement+jwt').send(jwt);
};
