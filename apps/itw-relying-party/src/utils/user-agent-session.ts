import type { CookieSerializeOptions } from '@fastify/cookie';

/**
 * User-agent session binding for the presentation flow.
 *
 * IT Wallet 1.4 requires the Relying Party to create `state` with sufficient
 * entropy, bind it to the user-agent session that started the flow, store it
 * server-side with a short expiration, and treat the transaction as complete
 * only if the Same Device redirect comes back *in that same session* —
 * otherwise it must reject the presentation.
 *
 * `state` was already a `randomUUID` held server-side under a short TTL; what
 * this adds is the binding. The browser that calls
 * `POST /create-authorization-request` is handed an opaque identifier in a
 * cookie, the same value is stored on the request object row, and `/callback`
 * requires the two to agree.
 */

/** Cookie carrying the opaque user-agent session identifier. */
export const USER_AGENT_SESSION_COOKIE = 'rp_session';

/**
 * Lifetime of a presentation session, shared by the request object row and the
 * cookie bound to it so the browser never holds an identifier that outlives the
 * server-side state it points at.
 */
export const USER_AGENT_SESSION_TTL_SECONDS = 5 * 60;

/**
 * Attributes for the session cookie.
 *
 * `sameSite: 'lax'` rather than `'none'`: the wallet sends the user-agent back
 * to `/callback` as a top-level GET navigation, which Lax permits, so nothing
 * weaker is required. `secure` is unconditional — the Relying Party is served
 * over HTTPS only.
 */
export const userAgentSessionCookieOptions: CookieSerializeOptions = {
  httpOnly: true,
  maxAge: USER_AGENT_SESSION_TTL_SECONDS,
  path: '/',
  sameSite: 'lax',
  secure: true
};

/**
 * Whether a caller is the browser the request object was created for.
 *
 * The bare comparison, with no flow-type exemption: a caller that should be
 * bound at all is bound by this. `isSameUserSession` layers the Same
 * Device/Cross Device asymmetry on top for `/callback`, the one endpoint that
 * needs it.
 */
export function isBoundToUserSession(options: {
  cookieSessionId: string | undefined;
  storedSessionId: string | undefined;
}): boolean {
  const { cookieSessionId, storedSessionId } = options;

  return storedSessionId !== undefined && cookieSessionId === storedSessionId;
}

/**
 * Whether a redirect back to `/callback` belongs to the user-agent session that
 * started the flow.
 *
 * Only the Same Device flow is bound: in Cross Device the browser that started
 * the presentation is on another device and never navigates to `/callback`, so
 * demanding a cookie there would reject a nominal flow.
 *
 * This exemption is specific to `/callback` being reached by the wallet's
 * redirect. It does not apply to the Relying Party's own `/status` polling,
 * which is always driven by the browser that started the flow whatever the flow
 * type, and so binds through `isBoundToUserSession` directly.
 */
export function isSameUserSession(options: {
  cookieSessionId: string | undefined;
  flowType: 'cross-device' | 'same-device';
  storedSessionId: string | undefined;
}): boolean {
  const { cookieSessionId, flowType, storedSessionId } = options;

  if (flowType !== 'same-device') return true;

  return isBoundToUserSession({ cookieSessionId, storedSessionId });
}
