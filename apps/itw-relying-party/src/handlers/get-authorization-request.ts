import { createObservedEvent } from '@itw-conformance-tool/conformance';
import z from 'zod';

import type { FastifyReply, FastifyRequest } from 'fastify';

export const getAuthorizationRequestParamsSchema = z.object({
  state: z.uuid().describe('Authorization request state identifier.')
});

export type GetAuthorizationRequestParams = z.infer<typeof getAuthorizationRequestParamsSchema>;

export const getAuthorizationRequestResponseSchema = z.string().describe('Signed authorization request JWT.');

export const getAuthorizationRequestHandler = async (
  req: FastifyRequest<{ Params: GetAuthorizationRequestParams }>,
  reply: FastifyReply
): Promise<FastifyReply> => {
  const requestObjectRepository = req.server.repository.requestObject;
  const state = req.params.state;
  const requestObject = requestObjectRepository.get(state);

  await req.server.conformanceEventSink.emit(
    createObservedEvent({
      name: 'rp.request_object.requested',
      scenarioId: req.conformance?.correlation?.scenarioId ?? null,
      correlationId: state,
      service: 'relying-party',
      requestId: req.id,
      diagnostic: { endpoint: '/auth/request/:state' }
    })
  );

  requestObjectRepository.update(state, 'checking');
  return reply.code(200).header('content-type', 'application/oauth-authz-req+jwt').send(requestObject.jwt);
};
