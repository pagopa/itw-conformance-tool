import z from 'zod';

import { isBoundToUserSession, USER_AGENT_SESSION_COOKIE } from '../utils/user-agent-session.js';

import type { FastifyReply, FastifyRequest } from 'fastify';

export const getStatusParamsSchema = z.object({
  state: z.uuid().describe('Authorization request state identifier.')
});

export type GetStatusParams = z.infer<typeof getStatusParamsSchema>;

export const getStatusResponseSchema = z.object({
  redirect_uri: z
    .string()
    .describe('Relative or absolute URI the caller should navigate to for the current session status.'),
  values: z
    .array(z.record(z.string(), z.union([z.string(), z.null()])))
    .optional()
    .describe('Optional credential values returned after a verified presentation.')
});

export type GetStatusResponse = z.infer<typeof getStatusResponseSchema>;

export const getStatusHandler = async (
  req: FastifyRequest<{ Params: GetStatusParams }>,
  reply: FastifyReply
): Promise<FastifyReply | GetStatusResponse> => {
  const { state } = req.params;
  const requestObjectRepository = req.server.repository.requestObject;

  const requestObject = requestObjectRepository.find(state);

  // `state` is public: it travels inside the `request_uri` the engagement URL
  // carries, which is rendered into the QR code and shown on screen. This
  // endpoint hands back the disclosed credential values and deletes the session
  // row on the terminal branches below, so the poll is bound to the browser that
  // created the request object, exactly as `/callback` is.
  //
  // Bound for both flow types, unlike `/callback`: whichever flow is running,
  // the browser polling here is the one that called
  // `POST /create-authorization-request` — in Cross Device it is the page
  // displaying the QR code, not the device holding the wallet.
  //
  // A `state` that does not exist and one belonging to another browser are
  // answered identically, so polling cannot be used to discover which states
  // exist.
  if (
    !requestObject ||
    !isBoundToUserSession({
      cookieSessionId: req.cookies[USER_AGENT_SESSION_COOKIE],
      storedSessionId: requestObject.userAgentSessionId
    })
  ) {
    return reply.notFound();
  }

  const { flowType, redirectUri, status, values } = requestObject;

  switch (status) {
    case 'verified':
      // A verified VP token is not yet a completed transaction in Same Device:
      // IT Wallet 1.4 completes one only once the redirect returns in the
      // session that started the flow, so the poll waits for `/callback` to move
      // the row to `completed` and the presented values stay withheld until it
      // does. Reporting success here would let a presentation the wallet never
      // redirected back — or redirected back from an unbound webview, which
      // `/callback` marks `rejected` — still show as a success.
      //
      // Cross Device has no such redirect to wait for: the wallet is handed no
      // `redirect_uri` at all there and never navigates here, so a verified
      // token completes the transaction and this endpoint is the only signal the
      // polling page ever gets.
      if (flowType === 'same-device') {
        return {
          redirect_uri: '?response_code=checking'
        };
      }

      if (!redirectUri) {
        requestObjectRepository.delete(state);

        return {
          redirect_uri: 'error.html?response_code=unexpected'
        };
      }

      // Cross-device: the browser polling this endpoint lands on the static
      // success page. The instrumented redirect_uri (/callback) is followed only
      // by the wallet's user-agent in the same-device flow, where the full
      // response_code query is preserved.
      return {
        redirect_uri: 'success.html?response_code=success',
        values
      };

    // Same Device only: `/callback` records the redirect back arriving in the
    // bound session, which is the point the transaction is complete and the
    // values may be disclosed to the browser that started it.
    case 'completed':
      return {
        redirect_uri: 'success.html?response_code=success',
        values
      };

    case 'rejected':
      requestObjectRepository.delete(state);

      return {
        redirect_uri: 'rejected-error.html?response_code=rejected'
      };

    case 'denied':
      requestObjectRepository.delete(state);

      return {
        redirect_uri: 'error.html?response_code=denied'
      };

    case 'expired':
      requestObjectRepository.delete(state);

      return {
        redirect_uri: 'timeout.html?response_code=expired'
      };

    case 'checking':
      return {
        redirect_uri: '?response_code=checking'
      };

    default:
      return {
        redirect_uri: '?response_code=pending'
      };
  }
};
