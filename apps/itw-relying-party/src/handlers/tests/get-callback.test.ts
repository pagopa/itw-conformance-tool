import { randomBytes, randomUUID } from 'node:crypto';

import Fastify from 'fastify';
import { describe, expect, it } from 'vitest';

import callbackRoute from '../../routes/callback.js';

import type { ObservedEvent } from '@itw-conformance-tool/conformance';

const RP_BASE_URL = 'https://rp.example.org';
/** The `redirect_uris` entry the Entity Configuration attests. */
const ATTESTED_REDIRECT_URI = `${RP_BASE_URL}/callback`;

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

async function buildApp(stored: { redirectUri?: string; status: string } | undefined) {
  const app = Fastify();
  const events: ObservedEvent[] = [];

  app.decorate('repository', {
    requestObject: {
      get: () => {
        if (!stored) throw new Error('Request object not found');
        return stored;
      }
    }
  });
  app.decorate('conformanceEventSink', {
    emit: async (event: ObservedEvent) => {
      events.push(event);
    }
  });

  await app.register(callbackRoute);
  await app.ready();

  return { app, events };
}

describe('GET /callback', () => {
  it('accepts the redirect_uri the Relying Party issued and records the follow', async () => {
    const state = randomUUID();
    const responseCode = randomBytes(32).toString('hex');
    const redirectUri = buildRedirectUri(state, responseCode);
    const { app, events } = await buildApp({ redirectUri: redirectUri.toString(), status: 'verified' });

    const response = await app.inject({ method: 'GET', url: `${redirectUri.pathname}${redirectUri.search}` });

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

    const response = await app.inject({
      method: 'GET',
      url: `/callback?state=${state}&response_code=${randomBytes(32).toString('hex')}`
    });

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

    const response = await app.inject({ method: 'GET', url: `/callback?state=${state}&response_code=${responseCode}` });

    expect(response.headers['location']).toBe('/error.html');
    expect(events.find((event) => event.name === 'rp.redirect.followed')).toBeUndefined();

    await app.close();
  });

  it('rejects an unknown session without failing the request', async () => {
    const { app, events } = await buildApp(undefined);

    const response = await app.inject({
      method: 'GET',
      url: `/callback?state=${randomUUID()}&response_code=${randomBytes(32).toString('hex')}`
    });

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
});
