import { afterEach, describe, expect, it, vi } from 'vitest';

import erasureRoute from '../../routes/erasure.js';
import requestObjectRoute from '../../routes/request-object.js';
import { buildRpRouteApp } from '../helpers/rp-route-app.js';

describe('WP_117a - Erasure request logging', () => {
  let ctx: Awaited<ReturnType<typeof buildRpRouteApp>>;

  afterEach(async () => {
    await ctx?.app.close();
  });

  it('logs timestamp, RP identifier and requested attributes for each erasure request', async () => {
    ctx = await buildRpRouteApp(requestObjectRoute, {
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
      url: `/auth/erasure?state=${state}&callback_url=${encodeURIComponent('https://wallet.example.org/after-erasure')}&attributes=family_name,given_name`
    });
    expect(res.statusCode).toBe(204);

    expect(logSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        attributes: ['family_name', 'given_name'],
        rpId: 'http://localhost:8080',
        state,
        timestamp: expect.any(String)
      }),
      'Erasure request received'
    );
  });
});
