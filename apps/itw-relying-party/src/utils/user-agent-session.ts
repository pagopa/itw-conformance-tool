import { randomUUID } from 'node:crypto';

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

/** Lifetime of the server-side presentation state a request object row holds. */
export const USER_AGENT_SESSION_TTL_SECONDS = 5 * 60;

/**
 * Grace the cookie keeps beyond the row it is bound to.
 *
 * The row is only moved to `expired` by a sweep that runs every 10 seconds, and
 * `/status` answers that status with the timeout redirect. Expiring the cookie
 * at the row's own TTL would make that branch unreachable: the browser drops the
 * cookie at the very moment the row falls due, so the poll that should have been
 * told the presentation timed out arrives unbound and is answered 404 instead.
 * The grace outlives the sweep interval by a wide margin, so the browser is
 * still bound when the row it started turns `expired`.
 */
export const USER_AGENT_SESSION_COOKIE_GRACE_SECONDS = 60;

/** Lifetime of the cookie carrying the binding, row TTL plus the grace above. */
export const USER_AGENT_SESSION_COOKIE_TTL_SECONDS =
  USER_AGENT_SESSION_TTL_SECONDS + USER_AGENT_SESSION_COOKIE_GRACE_SECONDS;

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
  maxAge: USER_AGENT_SESSION_COOKIE_TTL_SECONDS,
  path: '/',
  sameSite: 'lax',
  secure: true
};

/** Shape of a minted identifier, used to reject a value the RP never issued. */
const USER_AGENT_SESSION_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * The identifier a new request object binds to.
 *
 * A browser already carrying a live session keeps it, because the binding is to
 * the user-agent session rather than to a single transaction. Minting a fresh
 * value per engagement would overwrite the one cookie the browser holds, so
 * starting a second flow in another tab would unbind every flow already running:
 * their `/status` polls would begin answering 404, and a Same Device redirect
 * belonging to one of them would be rejected against the newest value.
 *
 * Only a well-formed identifier is carried over. The cookie is `httpOnly` and
 * host-only, so its value is one this Relying Party issued in all nominal cases;
 * checking the shape anyway keeps a hand-crafted request from choosing what gets
 * stored on the row.
 */
export function resolveUserAgentSessionId(cookieSessionId: string | undefined): string {
  return cookieSessionId !== undefined && USER_AGENT_SESSION_ID_PATTERN.test(cookieSessionId)
    ? cookieSessionId
    : randomUUID();
}

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
