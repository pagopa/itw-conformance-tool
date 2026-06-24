import { afterEach, describe, expect, it } from 'vitest';

import erasureRoute from '../../routes/erasure.js';
import requestObjectRoute from '../../routes/request-object.js';
import statusRoute from '../../routes/status.js';
import { buildRpRouteApp } from '../helpers/rp-route-app.js';

const VALID_DCQL_BODY = {
  dcqlQuery: {
    credentials: [{ id: 'pid', format: 'dc+sd-jwt' }]
  },
  flow_type: 'cross-device'
};

function requireSearchParam(url: URL, name: string): string {
  const value = url.searchParams.get(name);
  if (!value) {
    throw new Error(`Missing ${name} query parameter`);
  }
  return value;
}

describe('WP_118 - User redirect and callback', () => {
  let ctx: Awaited<ReturnType<typeof buildRpRouteApp>>;

  afterEach(async () => {
    await ctx?.app.close();
  });

  it('returns redirect_uri on callback and exposes it via /status/:state', async () => {
    ctx = await buildRpRouteApp(requestObjectRoute, {
      setup: async (app) => {
        await app.register(erasureRoute);
        await app.register(statusRoute);
      }
    });

    const requestObjectRes = await ctx.app.inject({
      method: 'POST',
      url: '/request-object',
      payload: VALID_DCQL_BODY
    });
    expect(requestObjectRes.statusCode).toBe(200);

    const { url } = requestObjectRes.json<{ url: string }>();
    const state = requireSearchParam(new URL(url), 'state');

    const redirectRes = await ctx.app.inject({
      method: 'GET',
      url: `/auth/erasure?state=${state}&callback_uri=${encodeURIComponent('https://wallet.example.org/erasure-callback')}`
    });
    expect(redirectRes.statusCode).toBe(200);
    expect(redirectRes.json<{ callback_uri: string }>().callback_uri).toContain(`state=${state}`);

    const callbackRes = await ctx.app.inject({
      method: 'POST',
      url: '/auth/erasure/callback',
      payload: {
        state,
        outcome: 'success',
        redirect_uri: 'https://wallet.example.org/after-erasure?response_code=success'
      }
    });

    expect(callbackRes.statusCode).toBe(200);
    const callbackBody = callbackRes.json<{ redirect_uri: string }>();
    expect(callbackBody.redirect_uri).toContain('after-erasure');
    expect(callbackBody.redirect_uri).toContain('response_code=success');

    const statusRes = await ctx.app.inject({ method: 'GET', url: `/status/${state}` });
    expect(statusRes.statusCode).toBe(200);
    expect(statusRes.json<{ redirect_uri: string }>().redirect_uri).toBe(callbackBody.redirect_uri);
  });
});
