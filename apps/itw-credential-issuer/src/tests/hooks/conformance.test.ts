import FastifyRateLimit from '@fastify/rate-limit';
import Fastify from 'fastify';
import fp from 'fastify-plugin';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import conformanceHooks from '../../hooks/conformance.js';

import type { IConformanceSessionRepository, ConformanceCheck } from '@itw-conformance-tool/conformance';
import type { FastifyInstance, FastifyPluginAsync } from 'fastify';

const SESSION_ID = 'aaaaaaaa-0000-1111-2222-333344445555';
const REQUEST_URI = `urn:ietf:params:oauth:request_uri:${SESSION_ID}`;

function makeConformanceRepo(): IConformanceSessionRepository & {
  _sessions: Map<string, { status: string; checks: ConformanceCheck[] }>;
} {
  const _sessions = new Map<string, { status: string; checks: ConformanceCheck[] }>();
  return {
    _sessions,
    create: vi.fn(async (session) => {
      _sessions.set(session.sessionId, { status: session.status, checks: [...session.checks] });
    }),
    get: vi.fn(async (sessionId) => {
      const s = _sessions.get(sessionId);
      return s ? { sessionId, startedAt: new Date().toISOString(), status: s.status as never, checks: s.checks } : null;
    }),
    appendCheck: vi.fn(async (sessionId, check) => {
      const s = _sessions.get(sessionId);
      if (s?.status === 'OPEN') s.checks.push(check);
    }),
    close: vi.fn(async (sessionId, status) => {
      const s = _sessions.get(sessionId);
      if (s) s.status = status;
    })
  };
}

function makeMockDbClient(code?: string, requestUri?: string) {
  return {
    db: {
      prepare: vi.fn(() => ({
        get: vi.fn((arg?: string) => {
          if (code && arg === code && requestUri) {
            return { request_uri: requestUri };
          }
          return undefined;
        }),
        run: vi.fn(() => ({ changes: 0, lastInsertRowid: 0 }))
      }))
    }
  };
}

async function buildHookApp(
  route: FastifyPluginAsync,
  opts: {
    repo?: IConformanceSessionRepository;
    dbCode?: string;
    dbRequestUri?: string;
  } = {}
): Promise<{ app: FastifyInstance; repo: ReturnType<typeof makeConformanceRepo> }> {
  const repo = (opts.repo as ReturnType<typeof makeConformanceRepo>) ?? makeConformanceRepo();
  const app = Fastify({ logger: false });

  app.decorate('config', {
    BASE_URL_SCHEME: 'http',
    HOST: 'localhost',
    PORT: 3000,
    DATA_DIR: '/tmp',
    DB_CLEANUP_INTERVAL_MS: 60_000,
    AUTH_FLOW: 'l2plus' as const,
    HTTPS_ENABLED: false,
    TLS_CERT_PATH: '',
    TLS_KEY_PATH: ''
  });
  app.decorate('conformanceSessionRepository', repo);
  app.decorate('dbClient', makeMockDbClient(opts.dbCode, opts.dbRequestUri) as never);
  app.decorate('nonceRepository', {
    consume: vi.fn(async () => true),
    delete: vi.fn(async () => undefined),
    get: vi.fn(async () => undefined),
    insert: vi.fn(async () => undefined)
  });
  app.decorate('parRepository', {
    delete: vi.fn(async () => undefined),
    get: vi.fn(async () => undefined),
    getByMrtdAuthSession: vi.fn(async () => undefined),
    insert: vi.fn(async () => undefined),
    update: vi.fn(async () => undefined)
  });
  app.decorate('sessionRepository', {
    delete: vi.fn(async () => undefined),
    get: vi.fn(async () => undefined),
    insert: vi.fn(async () => undefined),
    update: vi.fn(async () => undefined)
  });
  app.decorate('issuerKeys', {
    signingKeysJwks: { keys: [] },
    iacaCertPem: '',
    iacaKeyPem: ''
  });

  await app.register(FastifyRateLimit, { global: false });
  // Register a stub 'db' plugin to satisfy the conformanceHooks dependency declaration
  await app.register(fp(async () => { /* stub db plugin for tests */ }, { name: 'db' }));
  await app.register(conformanceHooks);
  await app.register(route);
  await app.ready();

  return { app, repo };
}

describe('conformanceHooks', () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('PAR step (POST /as/par)', () => {
    let app: FastifyInstance;
    let repo: ReturnType<typeof makeConformanceRepo>;

    beforeEach(async () => {
      const parRoute: FastifyPluginAsync = async (a) => {
        a.post('/as/par', async (_req, reply) => {
          return reply.code(201).send({ request_uri: REQUEST_URI, expires_in: 60 });
        });
      };
      ({ app, repo } = await buildHookApp(parRoute));
    });

    afterEach(() => app.close());

    it('creates a conformance session on PAR 201 response', async () => {
      const res = await app.inject({ method: 'POST', url: '/as/par', body: {} });
      expect(res.statusCode).toBe(201);

      // Allow fire-and-forget promises to settle
      await new Promise((r) => setImmediate(r));

      expect(repo.create).toHaveBeenCalledWith(expect.objectContaining({ sessionId: SESSION_ID, status: 'OPEN' }));
    });

    it('appends a PASS check for PAR on success', async () => {
      await app.inject({ method: 'POST', url: '/as/par', body: {} });
      await new Promise((r) => setImmediate(r));

      expect(repo.appendCheck).toHaveBeenCalledWith(
        SESSION_ID,
        expect.objectContaining({ step: 'PAR', result: 'PASS', phase: 'ISSUANCE' })
      );
    });

    it('does not create a session when PAR returns 400', async () => {
      const failRoute: FastifyPluginAsync = async (a) => {
        a.post('/as/par', async (_req, reply) => {
          return reply.code(400).send({ error: 'invalid_request' });
        });
      };
      const { app: a2, repo: r2 } = await buildHookApp(failRoute);
      await a2.inject({ method: 'POST', url: '/as/par', body: {} });
      await new Promise((r) => setImmediate(r));

      expect(r2.create).not.toHaveBeenCalled();
      await a2.close();
    });

    it('returns original response payload unchanged', async () => {
      const res = await app.inject({ method: 'POST', url: '/as/par', body: {} });
      expect(res.json()).toEqual({ request_uri: REQUEST_URI, expires_in: 60 });
    });
  });

  describe('AUTHORIZE step (GET /authorize)', () => {
    let app: FastifyInstance;
    let repo: ReturnType<typeof makeConformanceRepo>;

    beforeEach(async () => {
      const authorizeRoute: FastifyPluginAsync = async (a) => {
        a.get('/authorize', async (_req, reply) => reply.code(200).send({}));
      };
      ({ app, repo } = await buildHookApp(authorizeRoute));
      repo._sessions.set(SESSION_ID, { status: 'OPEN', checks: [] });
    });

    afterEach(() => app.close());

    it('appends a PASS check when handler returns 200', async () => {
      const res = await app.inject({
        method: 'GET',
        url: `/authorize?client_id=test&request_uri=${encodeURIComponent(REQUEST_URI)}`
      });
      expect(res.statusCode).toBe(200);
      await new Promise((r) => setImmediate(r));

      expect(repo.appendCheck).toHaveBeenCalledWith(
        SESSION_ID,
        expect.objectContaining({ step: 'AUTHORIZE', result: 'PASS' })
      );
    });

    it('appends a FAIL check and closes session when handler returns 400', async () => {
      const failRoute: FastifyPluginAsync = async (a) => {
        a.get('/authorize', async (_req, reply) => reply.code(400).send({ error: 'invalid_request' }));
      };
      const { app: a2, repo: r2 } = await buildHookApp(failRoute);
      r2._sessions.set(SESSION_ID, { status: 'OPEN', checks: [] });

      await a2.inject({
        method: 'GET',
        url: `/authorize?client_id=test&request_uri=${encodeURIComponent(REQUEST_URI)}`
      });
      await new Promise((r) => setImmediate(r));

      expect(r2.appendCheck).toHaveBeenCalledWith(
        SESSION_ID,
        expect.objectContaining({ step: 'AUTHORIZE', result: 'FAIL', httpStatus: 400 })
      );
      expect(r2.close).toHaveBeenCalledWith(SESSION_ID, 'FAILED');
      await a2.close();
    });

    it('is a no-op for unknown request_uri', async () => {
      const res = await app.inject({ method: 'GET', url: '/authorize?client_id=x&request_uri=invalid-uri' });
      expect(res.statusCode).toBe(200);
      await new Promise((r) => setImmediate(r));

      expect(repo.appendCheck).not.toHaveBeenCalled();
    });
  });

  describe('CREDENTIAL step (POST /credential)', () => {
    let app: FastifyInstance;
    let repo: ReturnType<typeof makeConformanceRepo>;

    beforeEach(async () => {
      const credentialRoute: FastifyPluginAsync = async (a) => {
        a.post('/credential', async (_req, reply) => reply.code(200).send({ credential: 'test-cred' }));
      };
      ({ app, repo } = await buildHookApp(credentialRoute));
      repo._sessions.set(SESSION_ID, { status: 'OPEN', checks: [] });
    });

    afterEach(() => app.close());

    it('closes session as PASSED on CREDENTIAL 200', async () => {
      // Build a fake access_token JWT with jti = SESSION_ID
      const header = Buffer.from(JSON.stringify({ alg: 'ES256' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({ jti: 'test-jti-1', sub: 'wallet' })).toString('base64url');
      const fakeJwt = `${header}.${payload}.fakesig`;

      // Pre-populate tokenJtiMap by simulating TOKEN success via a helper
      // We do this by running a fake TOKEN route first to populate the map
      const tokenRoute: FastifyPluginAsync = async (a) => {
        a.post('/token', async (_req, reply) => reply.code(200).send({ access_token: fakeJwt, token_type: 'Bearer' }));
      };
      const credRoute2: FastifyPluginAsync = async (a) => {
        a.post('/credential', async (_req, reply) => reply.code(200).send({ credential: 'test-cred' }));
      };

      const tokenRepo = makeConformanceRepo();
      tokenRepo._sessions.set(SESSION_ID, { status: 'OPEN', checks: [] });

      const app2 = Fastify({ logger: false });
      app2.decorate('config', {
        BASE_URL_SCHEME: 'http' as const,
        HOST: 'localhost',
        PORT: 3000,
        DATA_DIR: '/tmp',
        DB_CLEANUP_INTERVAL_MS: 60_000,
        AUTH_FLOW: 'l2plus' as const,
        HTTPS_ENABLED: false,
        TLS_CERT_PATH: '',
        TLS_KEY_PATH: ''
      });
      app2.decorate('conformanceSessionRepository', tokenRepo);
      app2.decorate('dbClient', makeMockDbClient('test-code', REQUEST_URI) as never);
      app2.decorate('nonceRepository', {
        consume: vi.fn(async () => true),
        delete: vi.fn(async () => undefined),
        get: vi.fn(async () => undefined),
        insert: vi.fn(async () => undefined)
      });
      app2.decorate('parRepository', {
        delete: vi.fn(async () => undefined),
        get: vi.fn(async () => undefined),
        getByMrtdAuthSession: vi.fn(async () => undefined),
        insert: vi.fn(async () => undefined),
        update: vi.fn(async () => undefined)
      });
      app2.decorate('sessionRepository', {
        delete: vi.fn(async () => undefined),
        get: vi.fn(async () => undefined),
        insert: vi.fn(async () => undefined),
        update: vi.fn(async () => undefined)
      });
      app2.decorate('issuerKeys', { signingKeysJwks: { keys: [] }, iacaCertPem: '', iacaKeyPem: '' });

      await app2.register(FastifyRateLimit, { global: false });
      await app2.register(fp(async () => { /* stub db plugin for tests */ }, { name: 'db' }));
      await app2.register(conformanceHooks);
      await app2.register(tokenRoute);
      await app2.register(credRoute2);
      await app2.ready();

      // Step 1: TOKEN success populates jti map
      await app2.inject({
        method: 'POST',
        url: '/token',
        body: { code: 'test-code', grant_type: 'authorization_code', redirect_uri: 'https://wallet.example' }
      });
      await new Promise((r) => setImmediate(r));

      // Step 2: CREDENTIAL with Bearer token
      const credRes = await app2.inject({
        method: 'POST',
        url: '/credential',
        headers: { authorization: `Bearer ${fakeJwt}` },
        body: { proof: 'test' }
      });
      await new Promise((r) => setImmediate(r));

      expect(credRes.statusCode).toBe(200);
      expect(tokenRepo.close).toHaveBeenLastCalledWith(SESSION_ID, 'PASSED');
      await app2.close();
    });
  });

  describe('NONCE step (POST /nonce)', () => {
    it('correlates NONCE to the session via pendingNonceQueue populated by TOKEN', async () => {
      const header = Buffer.from(JSON.stringify({ alg: 'ES256' })).toString('base64url');
      const tokenPayload = Buffer.from(JSON.stringify({ jti: 'nonce-jti', sub: 'wallet' })).toString('base64url');
      const fakeJwt = `${header}.${tokenPayload}.fakesig`;

      const combinedRepo = makeConformanceRepo();
      combinedRepo._sessions.set(SESSION_ID, { status: 'OPEN', checks: [] });

      const app3 = Fastify({ logger: false });
      app3.decorate('config', {
        BASE_URL_SCHEME: 'http' as const,
        HOST: 'localhost',
        PORT: 3000,
        DATA_DIR: '/tmp',
        DB_CLEANUP_INTERVAL_MS: 60_000,
        AUTH_FLOW: 'l2plus' as const,
        HTTPS_ENABLED: false,
        TLS_CERT_PATH: '',
        TLS_KEY_PATH: ''
      });
      app3.decorate('conformanceSessionRepository', combinedRepo);
      app3.decorate('dbClient', makeMockDbClient('nonce-code', REQUEST_URI) as never);
      app3.decorate('nonceRepository', {
        consume: vi.fn(async () => true),
        delete: vi.fn(async () => undefined),
        get: vi.fn(async () => undefined),
        insert: vi.fn(async () => undefined)
      });
      app3.decorate('parRepository', {
        delete: vi.fn(async () => undefined),
        get: vi.fn(async () => undefined),
        getByMrtdAuthSession: vi.fn(async () => undefined),
        insert: vi.fn(async () => undefined),
        update: vi.fn(async () => undefined)
      });
      app3.decorate('sessionRepository', {
        delete: vi.fn(async () => undefined),
        get: vi.fn(async () => undefined),
        insert: vi.fn(async () => undefined),
        update: vi.fn(async () => undefined)
      });
      app3.decorate('issuerKeys', { signingKeysJwks: { keys: [] }, iacaCertPem: '', iacaKeyPem: '' });

      const tokenRoute: FastifyPluginAsync = async (a) => {
        a.post('/token', async (_req, reply) => reply.code(200).send({ access_token: fakeJwt, token_type: 'Bearer' }));
      };
      const nonceRoute: FastifyPluginAsync = async (a) => {
        a.post('/nonce', async (_req, reply) => reply.code(200).send({ c_nonce: 'generated-nonce' }));
      };

      await app3.register(FastifyRateLimit, { global: false });
      await app3.register(fp(async () => { /* stub db plugin for tests */ }, { name: 'db' }));
      await app3.register(conformanceHooks);
      await app3.register(tokenRoute);
      await app3.register(nonceRoute);
      await app3.ready();

      // TOKEN success populates the pendingNonceQueue
      await app3.inject({
        method: 'POST',
        url: '/token',
        body: { code: 'nonce-code', grant_type: 'authorization_code', redirect_uri: 'https://wallet.example' }
      });
      await new Promise((r) => setImmediate(r));

      // NONCE call should pick up SESSION_ID from the queue
      const nonceRes = await app3.inject({ method: 'POST', url: '/nonce', body: {} });
      await new Promise((r) => setImmediate(r));

      expect(nonceRes.statusCode).toBe(200);
      expect(combinedRepo.appendCheck).toHaveBeenCalledWith(
        SESSION_ID,
        expect.objectContaining({ step: 'NONCE', result: 'PASS', phase: 'ISSUANCE' })
      );
      await app3.close();
    });
  });

  describe('session lifecycle', () => {
    it('does not close session after AUTHORIZE success (intermediate step)', async () => {
      const authorizeRoute: FastifyPluginAsync = async (a) => {
        a.get('/authorize', async (_req, reply) => reply.code(200).send({}));
      };
      const { app: a, repo: r } = await buildHookApp(authorizeRoute);
      r._sessions.set(SESSION_ID, { status: 'OPEN', checks: [] });

      await a.inject({
        method: 'GET',
        url: `/authorize?client_id=test&request_uri=${encodeURIComponent(REQUEST_URI)}`
      });
      await new Promise((resolve) => setImmediate(resolve));

      expect(r.close).not.toHaveBeenCalled();
      await a.close();
    });

    it('closes session as FAILED on any step returning 400', async () => {
      const badPresRoute: FastifyPluginAsync = async (a) => {
        a.post('/presentation-response', async (_req, reply) => reply.code(400).send({ error: 'invalid_request' }));
      };
      const { app: a, repo: r } = await buildHookApp(badPresRoute);
      r._sessions.set(SESSION_ID, { status: 'OPEN', checks: [] });

      await a.inject({
        method: 'POST',
        url: `/presentation-response?request_uri=${encodeURIComponent(REQUEST_URI)}`,
        body: {}
      });
      await new Promise((resolve) => setImmediate(resolve));

      expect(r.close).toHaveBeenCalledWith(SESSION_ID, 'FAILED');
      await a.close();
    });

    it('does not interact with repo for untracked routes', async () => {
      const healthRoute: FastifyPluginAsync = async (a) => {
        a.get('/health', async (_req, reply) => reply.code(200).send({ ok: true }));
      };
      const { app: a, repo: r } = await buildHookApp(healthRoute);

      await a.inject({ method: 'GET', url: '/health' });
      await new Promise((resolve) => setImmediate(resolve));

      expect(r.create).not.toHaveBeenCalled();
      expect(r.appendCheck).not.toHaveBeenCalled();
      expect(r.close).not.toHaveBeenCalled();
      await a.close();
    });
  });
});
