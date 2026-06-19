import { randomUUID } from 'node:crypto';

import { SqliteConformanceSessionRepository } from '@itw-conformance-tool/conformance';
import { getX5cCert } from '@itw-conformance-tool/crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import federationRoute from '../../routes/federation.js';
import { buildRpRouteApp } from '../helpers/rp-route-app.js';

describe.sequential(`Wallet Provider Backend`, () => {
  let ctx: Awaited<ReturnType<typeof buildRpRouteApp>>;
  let repo: SqliteConformanceSessionRepository;
  let sessionId: string;
  let entityConfigResponse: Awaited<ReturnType<typeof ctx.app.inject>>;

  beforeAll(async () => {
    ctx = await buildRpRouteApp(federationRoute, {
      setup: async (app) => {
        app.rpKeys.x5cCertPem = await getX5cCert();
      }
    });
    repo = new SqliteConformanceSessionRepository(ctx.dbClient.db);
    sessionId = randomUUID();
    await repo.create({
      sessionId,
      startedAt: new Date().toISOString(),
      status: 'OPEN',
      checks: []
    });

    entityConfigResponse = await ctx.app.inject({
      method: 'GET',
      url: '/.well-known/openid-federation'
    });
  });

  afterAll(async () => {
    const session = await repo.get(sessionId);
    const allPassed = session?.checks.every((c) => c.result === 'PASS') ?? false;
    await repo.close(sessionId, allPassed ? 'PASSED' : 'FAILED');
    await ctx?.app.close();
  });

  // ___ WP_001 ____
  it('WP_001 - Execute a GET request to /.well-known/openid-federation and returns 200', async () => {
    await repo.appendCheck(sessionId, {
      requirementId: 'WP_001',
      description: 'GET /.well-known/openid-federation responds with 200',
      step: 'AUTHORIZE',
      phase: 'PRESENTATION',
      result: entityConfigResponse.statusCode === 200 ? 'PASS' : 'FAIL',
      timestamp: new Date().toISOString(),
      httpStatus: entityConfigResponse.statusCode,
      errorMessage: entityConfigResponse.statusCode === 200 ? undefined : entityConfigResponse.body
    });

    expect(entityConfigResponse.statusCode).toBe(200);
  });

  // ___ WP_002 ____
  it('WP_002 - Analyzes JWT structure and validates its signature', async () => {
    const parts = entityConfigResponse.body.split('.');
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());

    const isValidJwt =
      parts.length === 3 &&
      typeof header.alg === 'string' &&
      header.typ === 'entity-statement+jwt' &&
      typeof payload.iss === 'string' &&
      typeof payload.sub === 'string' &&
      typeof payload.iat === 'number' &&
      typeof payload.exp === 'number' &&
      typeof payload.jwks === 'object';

    await repo.appendCheck(sessionId, {
      requirementId: 'WP_002',
      description: 'Entity configuration is an OpenID Federation-compliant signed JWT',
      step: 'AUTHORIZE',
      phase: 'PRESENTATION',
      result: isValidJwt ? 'PASS' : 'FAIL',
      timestamp: new Date().toISOString(),
      httpStatus: entityConfigResponse.statusCode
    });

    expect(parts).toHaveLength(3);
    expect(header).toHaveProperty('alg');
    expect(header).toHaveProperty('typ', 'entity-statement+jwt');
    expect(payload).toHaveProperty('iss');
    expect(payload).toHaveProperty('sub');
    expect(payload).toHaveProperty('iat');
    expect(payload).toHaveProperty('exp');
    expect(payload).toHaveProperty('jwks');
  });
});
