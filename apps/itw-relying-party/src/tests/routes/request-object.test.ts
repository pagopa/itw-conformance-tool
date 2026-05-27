import { describe, it, expect, afterEach } from 'vitest';

import requestObjectRoute from '../../routes/request-object.js';
import { buildRpRouteApp } from '../helpers/rp-route-app.js';

const VALID_DCQL_BODY = {
  dcqlQuery: {
    credentials: [{ id: 'pid', format: 'dc+sd-jwt' }]
  },
  flow_type: 'cross-device'
};

describe('POST /request-object', () => {
  let ctx: Awaited<ReturnType<typeof buildRpRouteApp>>;

  afterEach(async () => {
    await ctx?.app.close();
  });

  it('returns 200 with a wallet URL on valid DCQL', async () => {
    ctx = await buildRpRouteApp(requestObjectRoute);
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/request-object',
      payload: VALID_DCQL_BODY
    });

    expect(res.statusCode).toBe(200);
    const body = res.json<{ url: string }>();
    expect(typeof body.url).toBe('string');

    const url = new URL(body.url);
    expect(url.searchParams.has('request_uri')).toBe(true);
    expect(url.searchParams.has('client_id')).toBe(true);
    expect(url.searchParams.has('state')).toBe(true);
  });

  it('request_uri points to /auth/request/:state', async () => {
    ctx = await buildRpRouteApp(requestObjectRoute);
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/request-object',
      payload: VALID_DCQL_BODY
    });
    const { url } = res.json<{ url: string }>();
    const parsedUrl = new URL(url);
    const requestUri = parsedUrl.searchParams.get('request_uri')!;
    expect(requestUri).toMatch(/\/auth\/request\/[0-9a-f-]+$/);
  });

  it('returns 400 when dcqlQuery is missing', async () => {
    ctx = await buildRpRouteApp(requestObjectRoute);
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/request-object',
      payload: { flow_type: 'cross-device' }
    });
    expect(res.statusCode).toBe(400);
  });

  it('accepts custom wallet_auth_base_uri', async () => {
    ctx = await buildRpRouteApp(requestObjectRoute);
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/request-object',
      payload: {
        ...VALID_DCQL_BODY,
        wallet_auth_base_uri: 'https://wallet.example.com/auth'
      }
    });
    expect(res.statusCode).toBe(200);
    const { url } = res.json<{ url: string }>();
    expect(url).toMatch(/^https:\/\/wallet\.example\.com\/auth/);
  });
});
