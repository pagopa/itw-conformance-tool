import { describe, it, expect, afterEach, beforeEach } from 'vitest';

import authRequestRoute from '../../routes/auth-request.js';
import { buildRpRouteApp } from '../helpers/rp-route-app.js';

describe('GET /auth/request/:state', () => {
  let ctx: Awaited<ReturnType<typeof buildRpRouteApp>>;

  beforeEach(async () => {
    ctx = await buildRpRouteApp(authRequestRoute);
  });

  afterEach(async () => {
    await ctx?.app.close();
  });

  it('returns 404 when session does not exist', async () => {
    const res = await ctx.app.inject({
      method: 'GET',
      url: '/auth/request/nonexistent-state'
    });
    expect(res.statusCode).toBe(404);
  });

  it('returns the request JWT with correct content-type for an existing session', async () => {
    // Create a session via the sessionService
    const state = 'test-state-abc';
    await ctx.sessionService.create({
      id: state,
      jwt: 'header.payload.signature',
      flowType: 'cross-device',
      ttlMs: 300_000
    });

    const res = await ctx.app.inject({
      method: 'GET',
      url: `/auth/request/${state}`
    });

    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toMatch(/application\/oauth-authz-req\+jwt/);
    expect(res.body).toBe('header.payload.signature');
  });

  it('transitions session to checking state after retrieval', async () => {
    const state = 'state-to-check';
    await ctx.sessionService.create({
      id: state,
      jwt: 'a.b.c',
      flowType: 'same-device',
      ttlMs: 300_000
    });

    await ctx.app.inject({ method: 'GET', url: `/auth/request/${state}` });

    const session = await ctx.sessionService.get(state);
    expect(session?.state).toBe('checking');
  });
});
