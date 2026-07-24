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

  // WP_082: the wallet retrieves the signed Request Object via HTTP GET on the
  // request_uri endpoint. Correlation is disabled, so the event is emitted
  // uncorrelated and the scenario adopts it as post-start evidence narrowed by
  // the endpoint/method diagnostics.
  await req.server.conformanceEventSink.emit(
    createObservedEvent({
      name: 'rp.request_object.requested',
      correlationId: null,
      service: 'relying-party',
      requestId: req.id,
      diagnostic: { endpoint: '/auth/request/:state', method: req.method }
    })
  );

  requestObjectRepository.update(state, 'checking');
  return reply.code(200).header('content-type', 'application/oauth-authz-req+jwt').send(requestObject.jwt);
};
