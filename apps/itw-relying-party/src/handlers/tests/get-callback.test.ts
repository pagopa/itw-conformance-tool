import { randomBytes, randomUUID } from 'node:crypto';

import FastifyCookie from '@fastify/cookie';
import Fastify from 'fastify';
import { describe, expect, it } from 'vitest';

import callbackRoute from '../../routes/callback.js';
import { USER_AGENT_SESSION_COOKIE } from '../../utils/user-agent-session.js';

import type { ObservedEvent } from '@itw-conformance-tool/conformance';

const RP_BASE_URL = 'https://rp.example.org';
/** The `redirect_uris` entry the Entity Configuration attests. */
const ATTESTED_REDIRECT_URI = `${RP_BASE_URL}/callback`;
/** Identifier the browser that started the flow carries in its session cookie. */
const USER_AGENT_SESSION_ID = 'user-agent-session-id';

/**
 * Builds the redirect URI exactly as `get-authorization-response.ts` does, so
 * the assertions below are about the contract between what the Relying Party
 * hands the wallet and what its own callback route accepts.
 */
function buildRedirectUri(state: string, responseCode: string): URL {
  const redirectUri = new URL(ATTESTED_REDIRECT_URI);
  redirectUri.searchParams.set('state', state);
  redirectUri.searchParams.set('response_code', responseCode);
  return redirectUri;
}

interface StoredRequestObject {
  flowType?: 'cross-device' | 'same-device';
  redirectUri?: string;
  status: string;
  userAgentSessionId?: string;
}

async function buildApp(stored: StoredRequestObject | undefined, failure?: Error) {
  const app = Fastify();
  const events: ObservedEvent[] = [];
  const updates: { requestObjectId: string; status: string }[] = [];

  app.decorate('repository', {
    requestObject: {
      find: () => {
        if (failure) throw failure;
        if (!stored) return undefined;
        // Same-device with a bound session unless a case says otherwise: that is
        // what `create-authorization-request` now writes for every flow.
        return { flowType: 'same-device', userAgentSessionId: USER_AGENT_SESSION_ID, ...stored };
      },
      update: (requestObjectId: string, status: string) => {
        updates.push({ requestObjectId, status });
      }
    }
  });
  app.decorate('conformanceEventSink', {
    emit: async (event: ObservedEvent) => {
      events.push(event);
    }
  });

  await app.register(FastifyCookie);
  await app.register(callbackRoute);
  await app.ready();

  return { app, events, updates };
}

/**
 * Follows a redirect the way the browser holding the session cookie would.
 * Pass `null` to follow it from a user-agent carrying no cookie at all.
 */
function followRedirect(
  app: Awaited<ReturnType<typeof buildApp>>['app'],
  url: string,
  userAgentSessionId: string | null = USER_AGENT_SESSION_ID
) {
  return app.inject({
    method: 'GET',
    url,
    ...(userAgentSessionId ? { cookies: { [USER_AGENT_SESSION_COOKIE]: userAgentSessionId } } : {})
  });
}

describe('GET /callback', () => {
  it('accepts the redirect_uri the Relying Party issued and records the follow', async () => {
    const state = randomUUID();
    const responseCode = randomBytes(32).toString('hex');
    const redirectUri = buildRedirectUri(state, responseCode);
    const { app, events } = await buildApp({ redirectUri: redirectUri.toString(), status: 'verified' });

    const response = await followRedirect(app, `${redirectUri.pathname}${redirectUri.search}`);

    expect(response.statusCode).toBe(302);
    expect(response.headers['location']).toBe('/success.html');

    const followed = events.find((event) => event.name === 'rp.redirect.followed');
    expect(followed?.diagnostic).toMatchObject({
      endpoint: '/callback',
      method: 'GET',
      redirectUri: redirectUri.toString(),
      responseCode
    });

    await app.close();
  });

  it('issues a redirect_uri whose base URI is exactly the attested one', async () => {
    const redirectUri = buildRedirectUri(randomUUID(), randomBytes(32).toString('hex'));

    // WP_094a: a wallet comparing the returned redirect_uri against
    // `openid_credential_verifier.redirect_uris` matches scheme, host and path
    // and ignores the query, which OpenID4VP requires it to carry the
    // response_code. A session identifier in the path would break that match.
    expect(`${redirectUri.origin}${redirectUri.pathname}`).toBe(ATTESTED_REDIRECT_URI);
    expect(redirectUri.pathname).toBe('/callback');
  });

  it('rejects a response_code that does not match the issued one', async () => {
    const state = randomUUID();
    const redirectUri = buildRedirectUri(state, randomBytes(32).toString('hex'));
    const { app, events } = await buildApp({ redirectUri: redirectUri.toString(), status: 'verified' });

    const response = await followRedirect(
      app,
      `/callback?state=${state}&response_code=${randomBytes(32).toString('hex')}`
    );

    expect(response.headers['location']).toBe('/error.html');
    expect(
      events.find((event) => event.name === 'rp.redirect.followed'),
      'a guessed response_code must not be recorded as a genuine redirect follow'
    ).toBeUndefined();

    await app.close();
  });

  it('rejects a follow for a presentation that was never verified', async () => {
    const state = randomUUID();
    const responseCode = randomBytes(32).toString('hex');
    const redirectUri = buildRedirectUri(state, responseCode);
    const { app, events } = await buildApp({ redirectUri: redirectUri.toString(), status: 'checking' });

    const response = await followRedirect(app, `/callback?state=${state}&response_code=${responseCode}`);

    expect(response.headers['location']).toBe('/error.html');
    expect(events.find((event) => event.name === 'rp.redirect.followed')).toBeUndefined();

    await app.close();
  });

  it('rejects an unknown session without failing the request', async () => {
    const { app, events } = await buildApp(undefined);

    const response = await followRedirect(
      app,
      `/callback?state=${randomUUID()}&response_code=${randomBytes(32).toString('hex')}`
    );

    expect(response.headers['location']).toBe('/error.html');
    expect(events.find((event) => event.name === 'rp.redirect.followed')).toBeUndefined();

    await app.close();
  });

  it('rejects a request that omits the session query parameters', async () => {
    const { app } = await buildApp({
      redirectUri: buildRedirectUri(randomUUID(), 'code').toString(),
      status: 'verified'
    });

    const missingState = await app.inject({ method: 'GET', url: '/callback?response_code=abc' });
    const missingCode = await app.inject({ method: 'GET', url: `/callback?state=${randomUUID()}` });

    expect(missingState.statusCode).toBe(400);
    expect(missingCode.statusCode).toBe(400);

    await app.close();
  });

  describe('user-agent session binding', () => {
    it('rejects a same-device redirect that returns in a different user session', async () => {
      const state = randomUUID();
      const responseCode = randomBytes(32).toString('hex');
      const redirectUri = buildRedirectUri(state, responseCode);
      const { app, events, updates } = await buildApp({
        flowType: 'same-device',
        redirectUri: redirectUri.toString(),
        status: 'verified'
      });

      const response = await followRedirect(
        app,
        `/callback?state=${state}&response_code=${responseCode}`,
        'another-session'
      );

      expect(response.headers['location']).toBe('/error.html');
      expect(updates, 'the presentation must be rejected, not left verified').toContainEqual({
        requestObjectId: state,
        status: 'rejected'
      });

      // The follow is still observed. WP_094 requires this event as evidence and
      // WP_094a as a forbidden continuation, so suppressing it here would make a
      // wallet that opens the redirect outside the original browser silently
      // unobservable rather than merely session-mismatched.
      const followed = events.find((event) => event.name === 'rp.redirect.followed');
      expect(followed, 'the rejected follow must still be recorded as evidence').toBeDefined();
      expect(followed?.diagnostic).toMatchObject({ endpoint: '/callback', method: 'GET', responseCode });

      await app.close();
    });

    it('rejects a same-device redirect that carries no session cookie at all', async () => {
      const state = randomUUID();
      const responseCode = randomBytes(32).toString('hex');
      const redirectUri = buildRedirectUri(state, responseCode);
      const { app, events } = await buildApp({
        flowType: 'same-device',
        redirectUri: redirectUri.toString(),
        status: 'verified'
      });

      const response = await followRedirect(app, `/callback?state=${state}&response_code=${responseCode}`, null);

      expect(response.headers['location']).toBe('/error.html');
      expect(
        events.find((event) => event.name === 'rp.redirect.followed'),
        'the rejected follow must still be recorded as evidence'
      ).toBeDefined();

      await app.close();
    });

    it('does not bind the cross-device flow to a user session', async () => {
      const state = randomUUID();
      const responseCode = randomBytes(32).toString('hex');
      const redirectUri = buildRedirectUri(state, responseCode);
      const { app, events, updates } = await buildApp({
        flowType: 'cross-device',
        redirectUri: redirectUri.toString(),
        status: 'verified'
      });

      // The browser that started a cross-device presentation is on another
      // device and never navigates here, so requiring its cookie would reject a
      // nominal flow.
      const response = await followRedirect(app, `/callback?state=${state}&response_code=${responseCode}`, null);

      expect(response.headers['location']).toBe('/success.html');
      // Completed rather than rejected: the cookie is exempt in Cross Device, so
      // arriving without one is a valid follow and completes the transaction.
      expect(updates).toEqual([{ requestObjectId: state, status: 'completed' }]);
      expect(events.find((event) => event.name === 'rp.redirect.followed')).toBeDefined();

      await app.close();
    });

    it('records the transaction as completed when the redirect returns in the session', async () => {
      const state = randomUUID();
      const responseCode = randomBytes(32).toString('hex');
      const redirectUri = buildRedirectUri(state, responseCode);
      const { app, updates } = await buildApp({ redirectUri: redirectUri.toString(), status: 'verified' });

      const response = await followRedirect(app, `${redirectUri.pathname}${redirectUri.search}`);

      expect(response.headers['location']).toBe('/success.html');
      // Completion is what `/status` waits for before releasing the values to
      // the Same Device browser that started the flow.
      expect(updates).toEqual([{ requestObjectId: state, status: 'completed' }]);

      await app.close();
    });

    it('lets a repository failure surface instead of redirecting to the error page', async () => {
      const state = randomUUID();
      const responseCode = randomBytes(32).toString('hex');
      const { app } = await buildApp({ status: 'verified' }, new Error('database is unavailable'));

      // The error page is the answer to a redirect that does not check out, not
      // to an outage: swallowing one as the other hides it from the logs.
      const response = await followRedirect(app, `/callback?state=${state}&response_code=${responseCode}`);

      expect(response.statusCode).toBe(500);

      await app.close();
    });
  });
});
