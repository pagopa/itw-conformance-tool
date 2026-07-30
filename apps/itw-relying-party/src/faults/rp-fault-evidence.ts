import { createObservedEvent } from '@itw-conformance-tool/conformance';
import { sha256HashArtifact } from '@itw-conformance-tool/utils';

import type { ActiveRpFault } from './rp-fault-store.js';
import type { FastifyRequest } from 'fastify';

/**
 * Records that a Relying Party fault profile was applied to an outgoing
 * artifact. Callers must emit this only after the mutated artifact was built
 * successfully, so a failure never surfaces as a successfully applied fault.
 *
 * The diagnostic carries safe data only: the affected endpoint, the profile
 * type, the owning scenario, the resolved specification version, and a
 * SHA-256 hash of the serialized artifact — never the artifact itself, keys,
 * credentials, or tokens. Correlation is disabled tool-wide, so the event is
 * emitted uncorrelated and adopted by scenarios as post-start evidence
 * narrowed by these diagnostics.
 */
export async function emitRpFaultApplied(
  req: FastifyRequest,
  input: {
    artifact: string;
    diagnostic?: Record<string, unknown>;
    endpoint: string;
    fault: ActiveRpFault;
  }
): Promise<void> {
  await req.server.conformanceEventSink.emit(
    createObservedEvent({
      name: 'rp.fault.applied',
      correlationId: null,
      service: 'relying-party',
      requestId: req.id,
      diagnostic: {
        endpoint: input.endpoint,
        faultProfileType: input.fault.profile.type,
        scenarioId: input.fault.scenarioId,
        resolvedSpecVersion: input.fault.specVersion,
        artifactHash: sha256HashArtifact(input.artifact),
        outcome: 'applied',
        ...input.diagnostic
      }
    })
  );
}
