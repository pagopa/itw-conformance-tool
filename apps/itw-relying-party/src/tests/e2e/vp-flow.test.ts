/**
 * E2E VP flow test — exercises the complete Relying Party presentation flow:
 *
 *   1. POST /request-object  → RP creates nonce + session, returns wallet URL
 *   2. GET  /auth/request/:state → wallet fetches signed request JWT
 *   3. POST /auth/response   → wallet presents encrypted VP token
 *   4. GET  /status/:state   → frontend polls and gets redirect_uri with response_code
 *
 * All steps run against an in-memory Fastify instance backed by real SQLite
 * (in a temp directory). No external services or real issuers are needed.
 */

import { mkdtempSync } from 'node:fs';
import { rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { DatabaseClient, SqliteNonceRepository, SqliteSessionRepository } from '@itw-conformance-tool/database';
import { SessionService } from '@itw-conformance-tool/rp';
import Fastify from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { generateEphemeralKeyPair } from '../../crypto/ephemeral-keys.js';
import authRequestRoute from '../../routes/auth-request.js';
import authResponseRoute from '../../routes/auth-response.js';
import healthRoute from '../../routes/health.js';
import requestObjectRoute from '../../routes/request-object.js';
import statusRoute from '../../routes/status.js';
import {
  TEST_AUTH_REQUEST_PEM,
  TEST_AUTH_RESPONSE_PEM,
  TEST_CLIENT_ID,
  createAuthResponseJwe
} from '../helpers/rp-route-app.js';

function requireSearchParam(url: URL, name: string): string {
  const value = url.searchParams.get(name);
  expect(value).toBeTruthy();
  if (value === null) {
    throw new Error(`Missing ${name} query parameter`);
  }
  return value;
}

// ---------------------------------------------------------------------------
// App fixture — starts a full RP app with all routes
// ---------------------------------------------------------------------------

async function buildFullRpApp() {
  const dataDir = mkdtempSync(join(tmpdir(), 'rp-e2e-'));
  const dbClient = new DatabaseClient({ dataDir });
  const sessionRepo = new SqliteSessionRepository(dbClient.db);
  const nonceRepo = new SqliteNonceRepository(dbClient.db);
  const sessionService = new SessionService(sessionRepo);
  const ephemeralKeys = await generateEphemeralKeyPair();

  const app = Fastify({ logger: false });

  app.decorate('config', {
    host: '0.0.0.0',
    port: 8080,
    baseUrl: TEST_CLIENT_ID,
    entityId: TEST_CLIENT_ID,
    dataDir,
    configFilePath: join(dataDir, 'config.ini'),
    trustAnchorUrl: 'https://trust-anchor.example.com',
    signingKeyPath: join(dataDir, 'signing-key.pem'),
    x5cCertPath: join(dataDir, 'x5c-cert.pem')
  });

  app.decorate('rpKeys', {
    authRequestPrivateKeyPem: TEST_AUTH_REQUEST_PEM,
    authResponsePrivateKeyPem: TEST_AUTH_RESPONSE_PEM,
    signingPrivateKeyPem: TEST_AUTH_REQUEST_PEM,
    x5cCertPem: '-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----\n'
  });

  app.decorate('trustChain', ['insecure-http-local-dev']);
  app.decorate('ephemeralKeys', ephemeralKeys);
  app.decorate('nonceRepository', nonceRepo);
  app.decorate('sessionService', sessionService);

  app.addHook('onClose', async () => {
    await dbClient.close();
    await rm(dataDir, { recursive: true, force: true });
  });

  await app.register(healthRoute);
  await app.register(requestObjectRoute);
  await app.register(authRequestRoute);
  await app.register(authResponseRoute);
  await app.register(statusRoute);
  await app.ready();

  return { app };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('VP flow — complete issuer ↔ relying party presentation', () => {
  let ctx: Awaited<ReturnType<typeof buildFullRpApp>>;

  beforeAll(async () => {
    ctx = await buildFullRpApp();
  });

  afterAll(async () => {
    await ctx?.app.close();
  });

  it('health check is reachable', async () => {
    const res = await ctx.app.inject({ method: 'GET', url: '/health' });
    expect(res.statusCode).toBe(200);
  });

  it('completes the full VP flow end-to-end', async () => {
    // ── Step 1: POST /request-object ─────────────────────────────────────
    const step1 = await ctx.app.inject({
      method: 'POST',
      url: '/request-object',
      payload: {
        dcqlQuery: { credentials: [{ id: 'pid', format: 'dc+sd-jwt' }] },
        flow_type: 'cross-device'
      }
    });
    expect(step1.statusCode).toBe(200);

    const { url: walletUrl } = step1.json<{ url: string }>();
    const parsedWalletUrl = new URL(walletUrl);
    const state = requireSearchParam(parsedWalletUrl, 'state');
    const requestUri = requireSearchParam(parsedWalletUrl, 'request_uri');
    expect(requestUri).toContain(`/auth/request/${state}`);

    // ── Step 2: GET /auth/request/:state ─────────────────────────────────
    const step2 = await ctx.app.inject({ method: 'GET', url: `/auth/request/${state}` });
    expect(step2.statusCode).toBe(200);
    expect(step2.headers['content-type']).toMatch(/application\/oauth-authz-req\+jwt/);

    // Extract nonce from the request JWT payload
    const [, payloadB64] = step2.body.split('.');
    const requestObjectPayload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString()) as Record<string, unknown>;
    const nonce = requestObjectPayload.nonce as string;
    expect(typeof nonce).toBe('string');

    // ── Step 3: POST /auth/response ───────────────────────────────────────
    const jwe = await createAuthResponseJwe({ nonce, state });

    const step3 = await ctx.app.inject({
      method: 'POST',
      url: '/auth/response',
      payload: { response: jwe }
    });
    expect(step3.statusCode).toBe(200);
    const { redirect_uri } = step3.json<{ redirect_uri: string }>();
    expect(redirect_uri).toContain('success.html');
    expect(redirect_uri).toContain('response_code=');

    // ── Step 4: GET /status/:state ────────────────────────────────────────
    const step4 = await ctx.app.inject({ method: 'GET', url: `/status/${state}` });
    expect(step4.statusCode).toBe(200);
    const statusBody = step4.json<{ redirect_uri: string }>();
    expect(statusBody.redirect_uri).toBe(redirect_uri);
  });

  it('reports pending before wallet fetches the request object', async () => {
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/request-object',
      payload: {
        dcqlQuery: { credentials: [{ id: 'pid', format: 'dc+sd-jwt' }] },
        flow_type: 'same-device'
      }
    });
    const { url } = res.json<{ url: string }>();
    const state = requireSearchParam(new URL(url), 'state');

    const statusRes = await ctx.app.inject({ method: 'GET', url: `/status/${state}` });
    expect(statusRes.json<{ redirect_uri: string }>().redirect_uri).toContain('response_code=pending');
  });

  it('reports error when nonce is replayed', async () => {
    // Create first request
    const firstReq = await ctx.app.inject({
      method: 'POST',
      url: '/request-object',
      payload: { dcqlQuery: { credentials: [{ id: 'pid', format: 'dc+sd-jwt' }] }, flow_type: 'cross-device' }
    });
    const state = requireSearchParam(new URL(firstReq.json<{ url: string }>().url), 'state');

    // Fetch the request object to get the nonce
    const reqObjRes = await ctx.app.inject({ method: 'GET', url: `/auth/request/${state}` });
    const [, payloadB64] = reqObjRes.body.split('.');
    const nonce = (JSON.parse(Buffer.from(payloadB64, 'base64url').toString()) as { nonce: string }).nonce;

    // Submit once (success) — nonce gets consumed
    const jwe1 = await createAuthResponseJwe({ nonce, state });
    const firstSubmit = await ctx.app.inject({
      method: 'POST',
      url: '/auth/response',
      payload: { response: jwe1 }
    });
    expect(firstSubmit.statusCode).toBe(200);

    // Create a second session, then replay the already-consumed nonce → expect 500
    const secondReq = await ctx.app.inject({
      method: 'POST',
      url: '/request-object',
      payload: { dcqlQuery: { credentials: [{ id: 'pid', format: 'dc+sd-jwt' }] }, flow_type: 'cross-device' }
    });
    const state2 = requireSearchParam(new URL(secondReq.json<{ url: string }>().url), 'state');
    await ctx.app.inject({ method: 'GET', url: `/auth/request/${state2}` });

    const jwe2 = await createAuthResponseJwe({ nonce, state: state2 });
    const replayRes = await ctx.app.inject({
      method: 'POST',
      url: '/auth/response',
      payload: { response: jwe2 }
    });
    expect(replayRes.statusCode).toBe(500);
  });
});
