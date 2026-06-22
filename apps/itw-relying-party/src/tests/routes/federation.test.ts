import { afterEach, describe, expect, it, vi } from 'vitest';

import federationRoute from '../../routes/federation.js';
import { buildRpRouteApp } from '../helpers/rp-route-app.js';

const mocked = vi.hoisted(() => ({
  createEntityConfigurationJwt: vi.fn().mockResolvedValue('entity-statement-jwt')
}));

vi.mock('../../federation/entity-configuration.js', () => ({
  createEntityConfigurationJwt: mocked.createEntityConfigurationJwt
}));

describe('GET /.well-known/openid-federation', () => {
  let ctx: Awaited<ReturnType<typeof buildRpRouteApp>>;

  afterEach(async () => {
    await ctx?.app.close();
    mocked.createEntityConfigurationJwt.mockClear();
  });

  it('uses the RP baseUrl as the published verifier entity id', async () => {
    ctx = await buildRpRouteApp(federationRoute, {
      baseUrl: 'https://127.0.0.1:8080',
      entityId: 'https://127.0.0.1:3000'
    });

    const res = await ctx.app.inject({
      method: 'GET',
      url: '/.well-known/openid-federation'
    });

    expect(res.statusCode).toBe(200);
    expect(res.body).toBe('entity-statement-jwt');
    expect(mocked.createEntityConfigurationJwt).toHaveBeenCalledWith(
      expect.objectContaining({
        entityId: 'https://127.0.0.1:8080'
      })
    );
  });
});
