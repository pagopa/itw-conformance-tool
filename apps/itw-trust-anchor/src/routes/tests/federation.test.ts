import { generateKeyPairSync } from 'node:crypto';

import Fastify from 'fastify';
import { decodeJwt } from 'jose';
import { describe, expect, it } from 'vitest';

import federationRoute from '../federation.js';

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
async function buildApp(federationPrivateJwk: JwkKey): Promise<FastifyInstance> {
  const app = Fastify();

  app.decorate('config', {
    baseUrl: TRUST_ANCHOR_BASE_URL,
    dataDir: '/tmp/unused',
    issuerEntityId: ISSUER_ENTITY_ID,
    rpEntityId: RP_ENTITY_ID
  });

  app.decorate('trustAnchorKeys', {
    federationPrivateJwk,
    issuerFederationJwk: {},
    rpFederationJwk: {}
  });

  await app.register(federationRoute);
  await app.ready();

  return app;
}

describe('GET /.well-known/openid-federation', () => {
  it('returns 200 with a signed entity configuration JWT', async () => {
    const app = await buildApp(generateFederationJwk('trust-anchor-federation-key'));

    const response = await app.inject({ method: 'GET', url: '/.well-known/openid-federation' });

    expect(response.statusCode).toBe(200);
    expect(response.headers['content-type']).toBe('application/entity-statement+jwt');

    const payload = decodeJwt(response.body);
    expect(payload.iss).toBe(TRUST_ANCHOR_BASE_URL);
    expect(payload.sub).toBe(TRUST_ANCHOR_BASE_URL);
    expect(payload.trust_mark_issuers).toEqual({
      [`${TRUST_ANCHOR_BASE_URL}/trust_marks/issuance/credential_issuer`]: [ISSUER_ENTITY_ID],
      [`${TRUST_ANCHOR_BASE_URL}/trust_marks/presentation/relying_party`]: [RP_ENTITY_ID]
    });

    await app.close();
  });

  it('returns 500 when the stored federation key is invalid', async () => {
    const app = await buildApp({ crv: 'P-256' });

    const response = await app.inject({ method: 'GET', url: '/.well-known/openid-federation' });

    expect(response.statusCode).toBe(500);
    expect(response.json()).toEqual({ error: 'internal_server_error' });

    await app.close();
  });
});
