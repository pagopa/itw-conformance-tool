import { createObservedEvent } from '@itw-conformance-tool/conformance';
import z from 'zod';

import type { FastifyReply, FastifyRequest } from 'fastify';

export const getCallbackParamsSchema = z.object({
  state: z.uuid().describe('Authorization request state identifier bound to the presentation.')
});

export type GetCallbackParams = z.infer<typeof getCallbackParamsSchema>;

export const getCallbackQuerystringSchema = z.object({
  response_code: z.string().min(1).describe('Opaque code issued in the authorization response redirect_uri.')
});

export type GetCallbackQuerystring = z.infer<typeof getCallbackQuerystringSchema>;

function extractResponseCode(redirectUri: string | undefined): string | null {
  if (!redirectUri) return null;
  try {
    return new URL(redirectUri).searchParams.get('response_code');
  } catch {
    return null;
  }
}

export const getCallbackHandler = async (
  req: FastifyRequest<{ Params: GetCallbackParams; Querystring: GetCallbackQuerystring }>,
  reply: FastifyReply
): Promise<FastifyReply> => {
  const { state } = req.params;
  const { response_code } = req.query;
  const requestObjectRepository = req.server.repository.requestObject;

  const requestObject = (() => {
    try {
      return requestObjectRepository.get(state);
    } catch {
      return undefined;
    }
  })();

  // Only a genuine follow of the RP-issued redirect_uri counts: the presentation
  // must be verified and the opaque response_code must match the one embedded in
  // the redirect_uri returned by the authorization response.
  const expectedResponseCode = extractResponseCode(requestObject?.redirectUri);
  const isValidFollow =
    requestObject?.status === 'verified' && expectedResponseCode !== null && expectedResponseCode === response_code;

  if (!isValidFollow) {
    return reply.redirect('/error.html');
  }

  // WP_094: the wallet followed the RP-supplied redirect_uri, landing the
  // user-agent back on the Relying Party. Correlated through the `state` carried
  // in the callback path.
  await req.server.conformanceEventSink.emit(
    createObservedEvent({
      name: 'rp.redirect.followed',
      scenarioId: req.conformance?.correlation?.scenarioId ?? null,
      correlationId: state,
      service: 'relying-party',
      requestId: req.id,
      diagnostic: { endpoint: '/callback/:state' }
    })
  );

  return reply.redirect('/success.html');
};
