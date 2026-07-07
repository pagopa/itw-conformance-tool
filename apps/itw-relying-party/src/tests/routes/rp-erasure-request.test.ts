import { afterEach, describe, expect, it, vi } from 'vitest';

import erasureRoute from '../../routes/erasure.js';
import requestObjectRoute from '../../routes/request-object.js';
import { buildRpRouteApp } from '../helpers/rp-route-app.js';

describe('RP local - Erasure request delivery', () => {
  let ctx: Awaited<ReturnType<typeof buildRpRouteApp>>;

  afterEach(async () => {
    await ctx?.app.close();
  });

  it('accepts a valid GET erasure request and returns 204 No Content', async () => {
    ctx = await buildRpRouteApp(requestObjectRoute, {
      baseUrl: 'https://localhost:8080',
      entityId: 'https://localhost:8080',
      setup: async (app) => {
        await app.register(erasureRoute);
      }
    });
    const logSpy = vi.spyOn(ctx.app.log, 'info');

    const createRes = await ctx.app.inject({
      method: 'POST',
      url: '/request-object',
      payload: {
        dcqlQuery: {
          credentials: [{ id: 'pid', format: 'dc+sd-jwt' }]
        },
        flow_type: 'cross-device'
      }
    });
    expect(createRes.statusCode).toBe(200);
    const { url } = createRes.json<{ url: string }>();
    const state = new URL(url).searchParams.get('state');
    expect(state).toBeTruthy();
    if (!state) {
      throw new Error('Missing state query parameter');
    }

    const res = await ctx.app.inject({
      method: 'GET',
      url: `/auth/erasure?state=${state}&callback_url=${encodeURIComponent('https://wallet.example.org/erasure-callback')}&attributes=family_name,given_name&attributes=birth_date`
    });

    expect(res.statusCode).toBe(204);
    expect(res.body).toBe('');

    expect(logSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        callbackUrl: 'https://wallet.example.org/erasure-callback',
        rpId: 'https://localhost:8080',
        state,
        attributes: ['family_name', 'given_name', 'birth_date'],
        timestamp: expect.any(String)
      }),
      'Erasure request received'
    );

    const session = await ctx.sessionService.get(state);
    expect(session?.state).toBe('verified');
    expect(session?.redirectUri).toBe('https://wallet.example.org/erasure-callback');
  });
});
