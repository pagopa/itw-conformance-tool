import { createObservedEvent } from '@itw-conformance-tool/conformance';
import z from 'zod';

import { isSameUserSession, USER_AGENT_SESSION_COOKIE } from '../utils/user-agent-session.js';

import type { FastifyReply, FastifyRequest } from 'fastify';

/**
 * Both members travel in the query string rather than the path so the callback
 * endpoint the wallet is handed keeps the exact base URI the Relying Party
 * attests in `openid_credential_verifier.redirect_uris` (WP_094a). OpenID4VP
 * already requires the returned `redirect_uri` to carry the `response_code`, so
 * a wallet compares scheme, host and path and ignores the query — a session
 * identifier in the path would make that comparison fail for a nominal flow.
 */
export const getCallbackQuerystringSchema = z.object({
  response_code: z.string().min(1).describe('Opaque code issued in the authorization response redirect_uri.'),
  state: z.uuid().describe('Authorization request state identifier bound to the presentation.')
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
  req: FastifyRequest<{ Querystring: GetCallbackQuerystring }>,
  reply: FastifyReply
): Promise<FastifyReply> => {
  const { response_code, state } = req.query;
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

  // IT Wallet 1.4 completes the transaction only when the Same Device redirect
  // returns in the user-agent session that started the flow, and requires the
  // presentation to be rejected otherwise.
  //
  // Deliberately kept out of `isValidFollow` above: that condition gates the
  // `rp.redirect.followed` emission, which WP_094 requires as evidence and
  // WP_094a requires as a forbidden continuation. Folding the session check into
  // it would suppress the event and silently break both — and a wallet that
  // opens the redirect in an in-app webview rather than the original browser
  // carries no cookie, which is a fact about the wallet worth observing, not a
  // reason to stop observing. So the follow is always recorded; only the
  // Relying Party's own verdict below depends on the session matching.
  const sameUserSession = isSameUserSession({
    cookieSessionId: req.cookies[USER_AGENT_SESSION_COOKIE],
    flowType: requestObject.flowType,
    storedSessionId: requestObject.userAgentSessionId
  });

  // WP_094: the wallet followed the RP-supplied redirect_uri, landing the
  // user-agent back on the Relying Party. Correlation is disabled, so the event
  // is emitted uncorrelated and adopted as post-start evidence narrowed by the
  // endpoint/method diagnostics.
  //
  // WP_094a reuses this very evidence with the opposite meaning: when the
  // `unattested-redirect-uri` fault publishes a `redirect_uris` list that does
  // not contain this endpoint, a request here means the wallet followed a
  // redirect_uri the federation never attested (see the WP_094a scenario, which
  // declares it as a forbidden continuation).
  await req.server.conformanceEventSink.emit(
    createObservedEvent({
      name: 'rp.redirect.followed',
      correlationId: null,
      service: 'relying-party',
      requestId: req.id,
      diagnostic: {
        endpoint: '/callback',
        method: req.method,
        redirectUri: requestObject?.redirectUri ?? null,
        responseCode: response_code
      }
    })
  );

  if (!sameUserSession) {
    requestObjectRepository.update(state, 'rejected');
    return reply.redirect('/error.html');
  }

  return reply.redirect('/success.html');
};
