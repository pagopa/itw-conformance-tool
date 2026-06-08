import { randomBytes } from 'node:crypto';

import { describe, it, expect, afterEach, beforeEach } from 'vitest';

import authResponseRoute from '../../routes/auth-response.js';
import { TEST_AUTH_RESPONSE_PEM, buildRpRouteApp, createAuthResponseJwe } from '../helpers/rp-route-app.js';

function makeStoredRequestJwt(state: string, nonce = randomBytes(32).toString('hex')): string {
  const header = Buffer.from(JSON.stringify({ alg: 'ES256', typ: 'oauth-authz-req+jwt' })).toString('base64url');
  const payload = Buffer.from(
    JSON.stringify({
      client_id: 'http://localhost:8080',
      dcql_query: { credentials: [{ id: 'pid', format: 'dc+sd-jwt' }] },
      nonce,
      response_mode: 'direct_post.jwt',
      response_type: 'vp_token',
      response_uri: 'http://localhost:8080/auth/response',
      state
    })
  ).toString('base64url');
  return `${header}.${payload}.signature`;
}

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

  it('returns 400 when both response and error payload fields are provided', async () => {
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/auth/response',
      payload: {
        response: 'a.b.c',
        error: 'access_denied',
        state: 'ambiguous-state'
      }
    });
    expect(res.statusCode).toBe(400);
  });

  it('marks session as rejected and returns empty body for an error response', async () => {
    const state = 'reject-test';
    await ctx.sessionService.create({
      id: state,
      jwt: makeStoredRequestJwt(state),
      flowType: 'cross-device',
      ttlMs: 300_000
    });
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

  it('returns empty body for an error response even when state is unknown', async () => {
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/auth/response',
      payload: { error: 'access_denied', error_description: 'User denied', state: 'unknown-session' }
    });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({});
  });

  it('returns 400 when response is not a valid JWE', async () => {
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/auth/response',
      payload: { response: 'not.a.valid.jwe.token' }
    });
    expect(res.statusCode).toBe(400);
  });

  it('returns redirect_uri and marks session verified for a valid encrypted VP response', async () => {
    const state = 'valid-vp-test';
    const nonce = randomBytes(32).toString('hex');
    await ctx.sessionService.create({
      id: state,
      jwt: makeStoredRequestJwt(state, nonce),
      flowType: 'cross-device',
      ttlMs: 300_000
    });
    await ctx.sessionService.update(state, 'checking');

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

  it('marks session as rejected and returns 400 when nonce is unknown', async () => {
    const state = 'unknown-nonce-test';
    const expectedNonce = randomBytes(32).toString('hex');
    await ctx.sessionService.create({
      id: state,
      jwt: makeStoredRequestJwt(state, expectedNonce),
      flowType: 'cross-device',
      ttlMs: 300_000
    });
    await ctx.sessionService.update(state, 'checking');

    // Build JWE with a nonce that was never inserted
    const jwe = await createAuthResponseJwe({ nonce: 'nonexistent-nonce-abc', state });

    const res = await ctx.app.inject({
      method: 'POST',
      url: '/auth/response',
      payload: { response: jwe }
    });

    expect(res.statusCode).toBe(400);

    const session = await ctx.sessionService.get(state);
    expect(session?.state).toBe('rejected');
  });

  it('marks session as rejected and returns 400 when KB-JWT uses an unsupported algorithm', async () => {
    const state = 'unsupported-kb-alg-test';
    const nonce = randomBytes(32).toString('hex');
    await ctx.sessionService.create({
      id: state,
      jwt: makeStoredRequestJwt(state, nonce),
      flowType: 'cross-device',
      ttlMs: 300_000
    });
    await ctx.sessionService.update(state, 'checking');

    await ctx.nonceRepo.insert(nonce, Date.now() + 300_000);

    const jwe = await createAuthResponseJwe({ nonce, state, kbJwtAlg: 'ES384' });

    const res = await ctx.app.inject({
      method: 'POST',
      url: '/auth/response',
      payload: { response: jwe }
    });

    expect(res.statusCode).toBe(400);

    const session = await ctx.sessionService.get(state);
    expect(session?.state).toBe('rejected');
  });
});
