import FastifyCookie, { type FastifyCookieOptions } from '@fastify/cookie';

/**
 * Required by the user-agent session binding: IT Wallet 1.4 has the Relying
 * Party bind `state` to the browser session that started the flow and accept
 * the Same Device redirect back only within that same session (see
 * `domain/user-agent-session.ts`).
 *
 * No `secret` is configured: the cookie carries an opaque random identifier
 * that is only ever compared against the value stored on the request object
 * row, so it needs no signature to be meaningful.
 */
export const autoConfig: FastifyCookieOptions = {};

export default FastifyCookie;
