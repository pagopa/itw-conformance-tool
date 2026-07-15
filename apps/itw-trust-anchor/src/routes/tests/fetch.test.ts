import { generateKeyPairSync } from 'node:crypto';

import Fastify from 'fastify';
import { decodeJwt } from 'jose';
import { describe, expect, it } from 'vitest';

import fetchRoute from '../fetch.js';

import type { JwkKey } from '../../plugins/keys.js';
import type { FastifyInstance } from 'fastify';

const TRUST_ANCHOR_BASE_URL = 'https://ta.example.org';
const ISSUER_ENTITY_ID = 'https://issuer.example.org';
const RP_ENTITY_ID = 'https://rp.example.org';

function generateFederationJwk(kid: string): JwkKey {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = privateKey.export({ format: 'jwk' }) as JwkKey;
  return { ...jwk, alg: 'ES256', kid, use: 'sig' };
}

// Boots a minimal Fastify instance decorated only with what the route under test needs,
// instead of the full app bootstrap (which requires real config.ini/env and key files on
// disk). This keeps the route test focused and avoids broad module mocks.
async function buildApp(options: { issuerFederationJwk: JwkKey; rpFederationJwk: JwkKey }): Promise<FastifyInstance> {
  const app = Fastify();

  app.decorate('config', {
    baseUrl: TRUST_ANCHOR_BASE_URL,
    dataDir: '/tmp/unused',
    issuerEntityId: ISSUER_ENTITY_ID,
    rpEntityId: RP_ENTITY_ID
  });

  app.decorate('trustAnchorKeys', {
    federationPrivateJwk: generateFederationJwk('trust-anchor-federation-key'),
    issuerFederationJwk: options.issuerFederationJwk,
    rpFederationJwk: options.rpFederationJwk
  });

  await app.register(fetchRoute);
  await app.ready();

  return app;
}

describe('GET /fetch', () => {
  it('returns a subordinate statement for a known issuer sub', async () => {
    const app = await buildApp({
      issuerFederationJwk: generateFederationJwk('issuer-signing-key'),
      rpFederationJwk: generateFederationJwk('federation-key')
    });

    const response = await app.inject({ method: 'GET', url: `/fetch?sub=${encodeURIComponent(ISSUER_ENTITY_ID)}` });

    expect(response.statusCode).toBe(200);
    expect(response.headers['content-type']).toBe('application/entity-statement+jwt');

    const payload = decodeJwt(response.body);
    expect(payload.iss).toBe(TRUST_ANCHOR_BASE_URL);
    expect(payload.sub).toBe(ISSUER_ENTITY_ID);

    await app.close();
  });

  it('returns a subordinate statement for a known rp sub', async () => {
    const app = await buildApp({
      issuerFederationJwk: generateFederationJwk('issuer-signing-key'),
      rpFederationJwk: generateFederationJwk('federation-key')
    });

    const response = await app.inject({ method: 'GET', url: `/fetch?sub=${encodeURIComponent(RP_ENTITY_ID)}` });

    expect(response.statusCode).toBe(200);
    const payload = decodeJwt(response.body);
    expect(payload.sub).toBe(RP_ENTITY_ID);

    await app.close();
  });

  it('returns 400 when sub is missing', async () => {
    const app = await buildApp({
      issuerFederationJwk: generateFederationJwk('issuer-signing-key'),
      rpFederationJwk: generateFederationJwk('federation-key')
    });

    const response = await app.inject({ method: 'GET', url: '/fetch' });

    expect(response.statusCode).toBe(400);

    await app.close();
  });

  it('returns 400 when sub is empty', async () => {
    const app = await buildApp({
      issuerFederationJwk: generateFederationJwk('issuer-signing-key'),
      rpFederationJwk: generateFederationJwk('federation-key')
    });

    const response = await app.inject({ method: 'GET', url: '/fetch?sub=' });

    expect(response.statusCode).toBe(400);

    await app.close();
  });

  it('returns 404 for an unknown sub', async () => {
    const app = await buildApp({
      issuerFederationJwk: generateFederationJwk('issuer-signing-key'),
      rpFederationJwk: generateFederationJwk('federation-key')
    });

    const response = await app.inject({ method: 'GET', url: '/fetch?sub=https://unknown.example.org' });

    expect(response.statusCode).toBe(404);
    expect(response.json()).toEqual({ error: 'not_found' });

    await app.close();
  });

  it('returns 500 when the resolved subject key is invalid', async () => {
    const app = await buildApp({
      issuerFederationJwk: { crv: 'P-256' },
      rpFederationJwk: generateFederationJwk('federation-key')
    });

    const response = await app.inject({ method: 'GET', url: `/fetch?sub=${encodeURIComponent(ISSUER_ENTITY_ID)}` });

    expect(response.statusCode).toBe(500);
    expect(response.json()).toEqual({ error: 'internal_server_error' });

    await app.close();
  });
});
