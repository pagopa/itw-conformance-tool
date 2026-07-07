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

describe('RP local - User redirect and callback flow', () => {
  let ctx: Awaited<ReturnType<typeof buildRpRouteApp>>;

  afterEach(async () => {
    await ctx?.app.close();
  });

  it('returns 204 from erasure endpoint and exposes callback URL via /status/:state', async () => {
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
    const callbackUrl = 'https://wallet.example.org/after-erasure';

    const redirectRes = await ctx.app.inject({
      method: 'GET',
      url: `/auth/erasure?state=${state}&callback_url=${encodeURIComponent(callbackUrl)}`
    });
    expect(redirectRes.statusCode).toBe(204);
    expect(redirectRes.body).toBe('');

    const statusRes = await ctx.app.inject({ method: 'GET', url: `/status/${state}` });
    expect(statusRes.statusCode).toBe(200);
    expect(statusRes.json<{ redirect_uri: string }>().redirect_uri).toBe(`${callbackUrl}?response_code=success`);
  });
});
