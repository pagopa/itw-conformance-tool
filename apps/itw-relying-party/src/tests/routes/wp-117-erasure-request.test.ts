import { afterEach, describe, expect, it, vi } from 'vitest';

import erasureRoute from '../../routes/erasure.js';
import requestObjectRoute from '../../routes/request-object.js';
import { buildRpRouteApp } from '../helpers/rp-route-app.js';

describe('WP_117 - Erasure request delivery', () => {
  let ctx: Awaited<ReturnType<typeof buildRpRouteApp>>;

  afterEach(async () => {
    await ctx?.app.close();
  });

  it('accepts a valid erasure request payload and logs required fields', async () => {
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
      method: 'POST',
      url: '/auth/erasure',
      payload: {
        state,
        callback_uri: 'https://wallet.example.org/erasure-callback',
        attributes: ['family_name', 'given_name']
      }
    });

    expect(res.statusCode).toBe(200);
    const body = res.json<{ callback_uri: string }>();
    expect(body.callback_uri).toContain('https://wallet.example.org/erasure-callback');
    expect(body.callback_uri).toContain(`state=${state}`);

    expect(logSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        rpId: 'http://localhost:8080',
        state,
        attributes: ['family_name', 'given_name'],
        timestamp: expect.any(String)
      }),
      'Erasure request received'
    );

    const session = await ctx.sessionService.get(state);
    expect(session?.state).toBe('checking');
  });
});
