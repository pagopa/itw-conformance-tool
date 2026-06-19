import { randomBytes, randomUUID } from 'node:crypto';

import { describe, it, expect, afterEach, beforeEach } from 'vitest';

import authResponseRoute from '../../routes/auth-response.js';
import { TEST_AUTH_RESPONSE_PEM, buildRpRouteApp, createAuthResponseJwe } from '../helpers/rp-route-app.js';

import type { ConformanceSession, IConformanceSessionRepository } from '@itw-conformance-tool/conformance';

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

  it('accepts vp_token when a DCQL entry contains an array of string credentials', async () => {
    const state = 'vp-token-dcql-array-test';
    const nonce = randomBytes(32).toString('hex');
    await ctx.sessionService.create({
      id: state,
      jwt: makeStoredRequestJwt(state, nonce),
      flowType: 'cross-device',
      ttlMs: 300_000
    });
    await ctx.sessionService.update(state, 'checking');
    await ctx.nonceRepo.insert(nonce, Date.now() + 300_000);

    const jwe = await createAuthResponseJwe({ nonce, state, vpTokenShape: 'dcql-array' });

    const res = await ctx.app.inject({
      method: 'POST',
      url: '/auth/response',
      payload: { response: jwe }
    });

    expect(res.statusCode).toBe(200);
    const session = await ctx.sessionService.get(state);
    expect(session?.state).toBe('verified');
  });
});

// ---------------------------------------------------------------------------
// Conformance hook integration — verify the hook is wired to the route
// ---------------------------------------------------------------------------

function makeTrackingConformanceRepo(): IConformanceSessionRepository & {
  closed: { sessionId: string; status: string }[];
} {
  const created: ConformanceSession[] = [];
  const closed: { sessionId: string; status: string }[] = [];
  return {
    closed,
    async create(session) {
      created.push(session);
    },
    async get(sessionId) {
      return created.find((s) => s.sessionId === sessionId) ?? null;
    },
    async appendCheck() {
      /* empty */
    },
    async close(sessionId, status) {
      closed.push({ sessionId, status });
    },
    async markOpenSessionsIncompleteOlderThan(_cutoffIso) {
      void _cutoffIso;
      return 0;
    }
  };
}

describe('POST /auth/response — conformance hook integration', () => {
  it('closes the conformance session as PASSED on a successful VP response', async () => {
    const repo = makeTrackingConformanceRepo();
    const ctx = await buildRpRouteApp(authResponseRoute, {
      authResponsePrivateKeyPem: TEST_AUTH_RESPONSE_PEM,
      conformanceSessionRepository: repo
    });

    const state = randomUUID();
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
    expect(repo.closed).toHaveLength(1);
    expect(repo.closed[0].sessionId).toBe(state);
    expect(repo.closed[0].status).toBe('PASSED');

    await ctx.app.close();
  });

  it('does not close the conformance session on a failed VP response', async () => {
    const repo = makeTrackingConformanceRepo();
    const ctx = await buildRpRouteApp(authResponseRoute, {
      authResponsePrivateKeyPem: TEST_AUTH_RESPONSE_PEM,
      conformanceSessionRepository: repo
    });

    const res = await ctx.app.inject({
      method: 'POST',
      url: '/auth/response',
      payload: { response: 'not.a.valid.jwe.token' }
    });

    expect(res.statusCode).toBe(400);
    expect(repo.closed).toHaveLength(0);

    await ctx.app.close();
  });
});
