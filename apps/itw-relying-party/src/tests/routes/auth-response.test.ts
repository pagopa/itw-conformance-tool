import { randomBytes } from 'node:crypto';

import { describe, it, expect, afterEach, beforeEach } from 'vitest';

import authResponseRoute from '../../routes/auth-response.js';
import { TEST_AUTH_RESPONSE_PEM, buildRpRouteApp, createAuthResponseJwe } from '../helpers/rp-route-app.js';

describe('POST /auth/response', () => {
  let ctx: Awaited<ReturnType<typeof buildRpRouteApp>>;

  beforeEach(async () => {
    ctx = await buildRpRouteApp(authResponseRoute, {
      authResponsePrivateKeyPem: TEST_AUTH_RESPONSE_PEM
    });
  });

  afterEach(async () => {
    await ctx?.app.close();
  });

  it('returns 400 on body that satisfies neither response nor error schema', async () => {
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/auth/response',
      payload: { unexpected_field: 'value' }
    });
    expect(res.statusCode).toBe(400);
  });

  it('marks session as rejected and returns empty body for an error response', async () => {
    const state = 'reject-test';
    await ctx.sessionService.create({ id: state, jwt: 'a.b.c', flowType: 'cross-device', ttlMs: 300_000 });
    await ctx.sessionService.update(state, 'checking');

    const res = await ctx.app.inject({
      method: 'POST',
      url: '/auth/response',
      payload: { error: 'access_denied', error_description: 'User denied', state }
    });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({});

    const session = await ctx.sessionService.get(state);
    expect(session?.state).toBe('rejected');
  });

  it('returns 500 when response is not a valid JWE', async () => {
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/auth/response',
      payload: { response: 'not.a.valid.jwe.token' }
    });
    expect(res.statusCode).toBe(500);
  });

  it('returns redirect_uri and marks session verified for a valid encrypted VP response', async () => {
    const state = 'valid-vp-test';
    await ctx.sessionService.create({ id: state, jwt: 'a.b.c', flowType: 'cross-device', ttlMs: 300_000 });
    await ctx.sessionService.update(state, 'checking');

    const nonce = randomBytes(32).toString('hex');
    await ctx.nonceRepo.insert(nonce, Date.now() + 300_000);

    const jwe = await createAuthResponseJwe({ nonce, state });

    const res = await ctx.app.inject({
      method: 'POST',
      url: '/auth/response',
      payload: { response: jwe }
    });

    expect(res.statusCode).toBe(200);
    const body = res.json<{ redirect_uri: string }>();
    expect(body.redirect_uri).toContain('success.html');
    expect(body.redirect_uri).toContain('response_code=');

    const session = await ctx.sessionService.get(state);
    expect(session?.state).toBe('verified');
  });

  it('marks session as denied and re-throws when nonce is unknown', async () => {
    const state = 'unknown-nonce-test';
    await ctx.sessionService.create({ id: state, jwt: 'a.b.c', flowType: 'cross-device', ttlMs: 300_000 });
    await ctx.sessionService.update(state, 'checking');

    // Build JWE with a nonce that was never inserted
    const jwe = await createAuthResponseJwe({ nonce: 'nonexistent-nonce-abc', state });

    const res = await ctx.app.inject({
      method: 'POST',
      url: '/auth/response',
      payload: { response: jwe }
    });

    expect(res.statusCode).toBe(500);

    const session = await ctx.sessionService.get(state);
    expect(session?.state).toBe('denied');
  });
});
