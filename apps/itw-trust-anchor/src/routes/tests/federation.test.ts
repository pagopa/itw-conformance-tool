import { generateKeyPairSync } from 'node:crypto';

import Fastify from 'fastify';
import { createLocalJWKSet, decodeJwt, decodeProtectedHeader, jwtVerify } from 'jose';
import { describe, expect, it } from 'vitest';

import { createTrustAnchorFaultStore } from '../../domain/index.js';
import federationRoute from '../federation.js';

import type { JwkKey } from '../../plugins/keys.js';
import type { FastifyInstance } from 'fastify';
import type { JWK } from 'jose';

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
function publicJwk(jwk: JwkKey): JWK {
  const { d, key_ops, ...publicKey } = jwk;
  void d;
  void key_ops;
  return publicKey as JWK;
}

async function buildApp(options: {
  faultFederationPrivateJwk?: JwkKey;
  federationPrivateJwk: JwkKey;
  scenarioId?: string;
}): Promise<{ app: FastifyInstance; events: Array<{ diagnostic?: Record<string, unknown>; name: string }> }> {
  const app = Fastify();
  const events: Array<{ diagnostic?: Record<string, unknown>; name: string }> = [];
  const trustAnchorFaultStore = createTrustAnchorFaultStore();

  if (options.scenarioId) {
    const activation = trustAnchorFaultStore.activate({
      scenarioId: options.scenarioId,
      specVersion: '1.4',
      profile: { type: 'entity-configuration-nonmatching-signing-key' }
    });
    expect(activation).toEqual({ ok: true });
  }

  app.decorate('config', {
    baseUrl: TRUST_ANCHOR_BASE_URL,
    dataDir: '/tmp/unused',
    issuerEntityId: ISSUER_ENTITY_ID,
    rpEntityId: RP_ENTITY_ID,
    walletProviderEntityId: 'https://127.0.0.1:3003'
  });

  app.decorate('trustAnchorKeys', {
    federationPrivateJwk: options.federationPrivateJwk,
    issuerFederationJwk: {},
    rpFederationJwk: {},
    walletProviderFederationJwk: {}
  });
  app.decorate('trustAnchorFaultStore', trustAnchorFaultStore);
  app.decorate('trustAnchorFaultKeys', {
    entityConfigurationNonmatchingSigningPrivateJwk:
      options.faultFederationPrivateJwk ?? generateFederationJwk('wp-017-nonmatching-trust-anchor-key')
  });
  app.decorate('conformanceEventSink', {
    emit: async (event) => {
      events.push({ name: event.name, diagnostic: event.diagnostic });
    }
  });

  await app.register(federationRoute);
  await app.ready();

  return { app, events };
}

describe('GET /.well-known/openid-federation', () => {
  it('returns 200 with a signed entity configuration JWT', async () => {
    const nominalKey = generateFederationJwk('trust-anchor-federation-key');
    const { app } = await buildApp({ federationPrivateJwk: nominalKey });

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
    expect(payload.jwks.keys).toEqual([publicJwk(nominalKey)]);

    await expect(
      jwtVerify(response.body, createLocalJWKSet({ keys: [publicJwk(nominalKey)] }), {
        issuer: TRUST_ANCHOR_BASE_URL,
        subject: TRUST_ANCHOR_BASE_URL
      })
    ).resolves.toBeDefined();

    await app.close();
  });

  it('returns 500 when the stored federation key is invalid', async () => {
    const { app } = await buildApp({ federationPrivateJwk: { crv: 'P-256' } });

    const response = await app.inject({ method: 'GET', url: '/.well-known/openid-federation' });

    expect(response.statusCode).toBe(500);
    expect(response.json()).toEqual({ error: 'internal_server_error' });

    await app.close();
  });

  it('uses the alternate self-consistent signing key while the WP_017 fault is active', async () => {
    const nominalKey = generateFederationJwk('trust-anchor-federation-key');
    const faultKey = generateFederationJwk('wp-017-nonmatching-trust-anchor-key');
    const { app, events } = await buildApp({
      federationPrivateJwk: nominalKey,
      faultFederationPrivateJwk: faultKey,
      scenarioId: 'wp-017-session'
    });

    const response = await app.inject({ method: 'GET', url: '/.well-known/openid-federation' });

    expect(response.statusCode).toBe(200);
    const header = decodeProtectedHeader(response.body);
    const payload = decodeJwt(response.body);

    expect(header.kid).toBe('wp-017-nonmatching-trust-anchor-key');
    expect(payload.jwks.keys).toEqual([publicJwk(faultKey)]);
    expect(payload.jwks.keys).not.toContainEqual(publicJwk(nominalKey));

    await expect(
      jwtVerify(response.body, createLocalJWKSet({ keys: [publicJwk(faultKey)] }), {
        issuer: TRUST_ANCHOR_BASE_URL,
        subject: TRUST_ANCHOR_BASE_URL
      })
    ).resolves.toBeDefined();

    await expect(
      jwtVerify(response.body, createLocalJWKSet({ keys: [publicJwk(nominalKey)] }), {
        issuer: TRUST_ANCHOR_BASE_URL,
        subject: TRUST_ANCHOR_BASE_URL
      })
    ).rejects.toThrow();

    const faultAppliedEvent = events.find((event) => event.name === 'trust_anchor.fault.applied');
    expect(faultAppliedEvent?.diagnostic).toEqual({
      artifactHash: expect.stringMatching(/^sha256:[A-Za-z0-9_-]+$/),
      endpoint: '/.well-known/openid-federation',
      faultProfileType: 'entity-configuration-nonmatching-signing-key',
      outcome: 'applied',
      scenarioId: 'wp-017-session',
      specVersion: '1.4'
    });
    expect(faultAppliedEvent?.diagnostic).not.toHaveProperty('jwt');
    expect(faultAppliedEvent?.diagnostic).not.toHaveProperty('jwk');

    await app.close();
  });

  it('returns to the nominal signing key after the WP_017 fault is deactivated', async () => {
    const nominalKey = generateFederationJwk('trust-anchor-federation-key');
    const faultKey = generateFederationJwk('wp-017-nonmatching-trust-anchor-key');
    const { app } = await buildApp({
      federationPrivateJwk: nominalKey,
      faultFederationPrivateJwk: faultKey,
      scenarioId: 'wp-017-session'
    });

    expect(app.trustAnchorFaultStore.deactivate({ scenarioId: 'wp-017-session' })).toEqual({ ok: true });

    const response = await app.inject({ method: 'GET', url: '/.well-known/openid-federation' });

    expect(response.statusCode).toBe(200);
    expect(decodeProtectedHeader(response.body).kid).toBe('trust-anchor-federation-key');
    expect(decodeJwt(response.body).jwks.keys).toEqual([publicJwk(nominalKey)]);

    await app.close();
  });
});
