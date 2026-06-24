import { randomBytes, randomUUID } from 'node:crypto';

import Fastify from 'fastify';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { registerAuthRequestConformanceHooks, registerAuthResponseConformanceHooks } from '../../hooks/conformance.js';
import { TEST_AUTH_RESPONSE_PEM, createAuthResponseJwe } from '../helpers/rp-route-app.js';

import type { ConformanceSession, IConformanceSessionRepository } from '@itw-conformance-tool/conformance';
import type { FastifyInstance } from 'fastify';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type TrackingRepo = IConformanceSessionRepository & {
  created: ConformanceSession[];
  closed: { sessionId: string; status: string }[];
};

function makeConformanceRepo(): TrackingRepo {
  const created: ConformanceSession[] = [];
  const closed: { sessionId: string; status: string }[] = [];
  return {
    created,
    closed,
    async create(session) {
      created.push(session);
    },
    async get(sessionId) {
      return created.find((s) => s.sessionId === sessionId) ?? null;
    },
    appendCheck: vi.fn(async () => Promise.resolve()),
    async close(sessionId, status) {
      closed.push({ sessionId, status });
    },
    async markOpenSessionsIncompleteOlderThan() {
      return 0;
    }
  };
}

async function buildRequestHookApp(withRepo = true): Promise<{ app: FastifyInstance; repo: TrackingRepo }> {
  const repo = makeConformanceRepo();
  const app = Fastify({ logger: false });

  if (withRepo) {
    app.decorate('conformanceSessionRepository', repo);
  }

  registerAuthRequestConformanceHooks(app);

  app.get<{ Params: { state: string } }>('/auth/request/:state', async (_req, reply) => {
    return reply.code(200).send('ok');
  });

  app.get<{ Params: { state: string } }>('/auth/request-fail/:state', async (_req, reply) => {
    return reply.code(404).send({ message: 'not found' });
  });

  await app.ready();
  return { app, repo };
}

async function buildResponseHookApp(withRepo = true): Promise<{ app: FastifyInstance; repo: TrackingRepo }> {
  const repo = makeConformanceRepo();
  const app = Fastify({ logger: false });

  if (withRepo) {
    app.decorate('conformanceSessionRepository', repo);
  }

  app.decorate('rpKeys', {
    authRequestPrivateKeyPem: '',
    authResponsePrivateKeyPem: TEST_AUTH_RESPONSE_PEM,
    federationPrivateKeyPem: '',
    signingPrivateKeyPem: '',
    x5cCertPem: ''
  });

  registerAuthResponseConformanceHooks(app);

  app.post('/auth/response', async (_req, reply) => {
    return reply.code(200).send({});
  });

  app.post('/auth/response-fail', async (_req, reply) => {
    return reply.code(500).send({ message: 'error' });
  });

  await app.ready();
  return { app, repo };
}

// ---------------------------------------------------------------------------
// registerAuthRequestConformanceHooks
// ---------------------------------------------------------------------------

describe('registerAuthRequestConformanceHooks', () => {
  let ctx: Awaited<ReturnType<typeof buildRequestHookApp>>;

  beforeEach(async () => {
    ctx = await buildRequestHookApp();
  });

  afterEach(async () => {
    await ctx.app.close();
  });

  it('opens a conformance session on 2xx when state is a valid UUID', async () => {
    const state = randomUUID();
    await ctx.app.inject({ method: 'GET', url: `/auth/request/${state}` });

    expect(ctx.repo.created).toHaveLength(1);
    expect(ctx.repo.created[0].sessionId).toBe(state);
    expect(ctx.repo.created[0].status).toBe('OPEN');
  });

  it('appends AUTHORIZE:PRESENTATION PASS check on 2xx', async () => {
    const state = randomUUID();
    await ctx.app.inject({ method: 'GET', url: `/auth/request/${state}` });

    expect(ctx.repo.appendCheck).toHaveBeenCalledOnce();
    expect(ctx.repo.appendCheck).toHaveBeenCalledWith(
      state,
      expect.objectContaining({
        phase: 'PRESENTATION',
        requirementId: 'IT-WALLET-1.4-§5.2.1',
        result: 'PASS',
        step: 'AUTHORIZE'
      })
    );
  });

  it('does not open a session on non-2xx response', async () => {
    const state = randomUUID();
    await ctx.app.inject({ method: 'GET', url: `/auth/request-fail/${state}` });

    expect(ctx.repo.created).toHaveLength(0);
  });

  it('does not open a session when state is not a valid UUID', async () => {
    await ctx.app.inject({ method: 'GET', url: '/auth/request/not-a-uuid' });

    expect(ctx.repo.created).toHaveLength(0);
  });

  it('does not throw when conformanceSessionRepository is not decorated', async () => {
    const { app } = await buildRequestHookApp(false);
    const state = randomUUID();
    const res = await app.inject({ method: 'GET', url: `/auth/request/${state}` });
    expect(res.statusCode).toBe(200);
    await app.close();
  });
});

// ---------------------------------------------------------------------------
// registerAuthResponseConformanceHooks
// ---------------------------------------------------------------------------

describe('registerAuthResponseConformanceHooks', () => {
  let ctx: Awaited<ReturnType<typeof buildResponseHookApp>>;

  beforeEach(async () => {
    ctx = await buildResponseHookApp();
  });

  afterEach(async () => {
    await ctx.app.close();
  });

  it('closes session as PASSED on 2xx with a valid JWE response body', async () => {
    const state = randomUUID();
    const nonce = randomBytes(32).toString('hex');
    const jwe = await createAuthResponseJwe({ nonce, state });

    await ctx.app.inject({
      method: 'POST',
      url: '/auth/response',
      payload: { response: jwe }
    });

    expect(ctx.repo.closed).toHaveLength(1);
    expect(ctx.repo.closed[0].sessionId).toBe(state);
    expect(ctx.repo.closed[0].status).toBe('PASSED');
  });

  it('appends PRESENTATION_RESPONSE:PRESENTATION PASS check on 2xx', async () => {
    const state = randomUUID();
    const nonce = randomBytes(32).toString('hex');
    const jwe = await createAuthResponseJwe({ nonce, state });

    await ctx.app.inject({
      method: 'POST',
      url: '/auth/response',
      payload: { response: jwe }
    });

    expect(ctx.repo.appendCheck).toHaveBeenCalledOnce();
    expect(ctx.repo.appendCheck).toHaveBeenCalledWith(
      state,
      expect.objectContaining({
        phase: 'PRESENTATION',
        requirementId: 'IT-WALLET-1.4-§5.2.2',
        result: 'PASS',
        step: 'PRESENTATION_RESPONSE'
      })
    );
  });

  it('closes session as FAILED and appends FAIL check on non-2xx response', async () => {
    const state = randomUUID();
    const nonce = randomBytes(32).toString('hex');
    const jwe = await createAuthResponseJwe({ nonce, state });

    await ctx.app.inject({
      method: 'POST',
      url: '/auth/response-fail',
      payload: { response: jwe }
    });

    expect(ctx.repo.closed).toHaveLength(1);
    expect(ctx.repo.closed[0].sessionId).toBe(state);
    expect(ctx.repo.closed[0].status).toBe('FAILED');
    expect(ctx.repo.appendCheck).toHaveBeenCalledOnce();
    expect(ctx.repo.appendCheck).toHaveBeenCalledWith(
      state,
      expect.objectContaining({
        phase: 'PRESENTATION',
        requirementId: 'IT-WALLET-1.4-§5.2.2',
        result: 'FAIL',
        step: 'PRESENTATION_RESPONSE'
      })
    );
  });

  it('does not close session when body has no response field', async () => {
    const state = randomUUID();
    await ctx.app.inject({
      method: 'POST',
      url: '/auth/response',
      payload: { error: 'access_denied', state }
    });

    expect(ctx.repo.closed).toHaveLength(0);
  });

  it('does not throw when conformanceSessionRepository is not decorated', async () => {
    const { app } = await buildResponseHookApp(false);
    const nonce = randomBytes(32).toString('hex');
    const jwe = await createAuthResponseJwe({ nonce, state: randomUUID() });
    const res = await app.inject({
      method: 'POST',
      url: '/auth/response',
      payload: { response: jwe }
    });
    expect(res.statusCode).toBe(200);
    await app.close();
  });

  it('does not throw when JWE cannot be decrypted', async () => {
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/auth/response',
      payload: { response: 'not.a.valid.jwe.token' }
    });

    expect(res.statusCode).toBe(200);
    expect(ctx.repo.closed).toHaveLength(0);
  });

  it('does not close session when JWE state is not a valid UUID', async () => {
    const nonce = randomBytes(32).toString('hex');
    const jwe = await createAuthResponseJwe({ nonce, state: 'not-a-uuid' });

    await ctx.app.inject({
      method: 'POST',
      url: '/auth/response',
      payload: { response: jwe }
    });

    expect(ctx.repo.closed).toHaveLength(0);
  });
});
