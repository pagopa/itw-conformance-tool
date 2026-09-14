import { generateKeyPairSync } from 'node:crypto';

import Fastify from 'fastify';
import { decodeJwt } from 'jose';
import { describe, expect, it } from 'vitest';

import fetchRoute from '../fetch.js';

import type { JwkKey } from '../../plugins/keys.js';
import type { JsonWebKey } from '@pagopa/io-wallet-oid-federation';
import type { FastifyInstance } from 'fastify';

const TRUST_ANCHOR_BASE_URL = 'https://ta.example.org';
const ISSUER_ENTITY_ID = 'https://issuer.example.org';
const RP_ENTITY_ID = 'https://rp.example.org';
const WALLET_PROVIDER_ENTITY_ID = 'https://127.0.0.1:3003';
const TRUST_ANCHOR_CERTIFICATE = 'trust-anchor-federation-certificate';
const WP_050A_METADATA_POLICY_EXCLUDED_CREDENTIAL_CONFIGURATION_ID = 'mso_mdoc_PersonIdentificationData';
const METADATA_POLICY_ALLOWED_CREDENTIAL_CONFIGURATION_ID = 'dc_sd_jwt_EuropeanDisabilityCard';

interface IssuerMetadataPolicyPayload {
  metadata_policy?: {
    openid_credential_issuer?: {
      credential_configurations_supported?: {
        essential?: unknown;
        subset_of?: unknown;
      };
    };
  };
}

function generateFederationJwk(kid: string): JwkKey {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = privateKey.export({ format: 'jwk' }) as JwkKey;
  return { ...jwk, alg: 'ES256', kid, use: 'sig' };
}

/** Stands in for the chain the `keys` plugin reads off disk; the route only
 * forwards it, so a recognisable placeholder is enough to assert it lands on the
 * right key. */
function certificateChain(name: string): string[] {
  return [`${name}-leaf`, `${name}-intermediate`];
}

/** A subordinate's key as the `keys` plugin hands it over: public, with its `kid`
 * already resolved and its chain already attached. */
function publishedJwk(privateJwk: JwkKey, name: string): JsonWebKey {
  const { d, key_ops, ...publicJwk } = privateJwk;
  void d;
  void key_ops;

  return { ...publicJwk, x5c: certificateChain(name) } as JsonWebKey;
}

// Boots a minimal Fastify instance decorated only with what the route under test needs,
// instead of the full app bootstrap (which requires real config.ini/env and key files on
// disk). This keeps the route test focused and avoids broad module mocks.
async function buildApp(options: {
  issuerFederationJwk: JwkKey;
  rpFederationJwk: JwkKey;
  walletProviderFederationJwk?: JwkKey;
}): Promise<FastifyInstance> {
  const app = Fastify();

  app.decorate('config', {
    baseUrl: TRUST_ANCHOR_BASE_URL,
    dataDir: '/tmp/unused',
    issuerEntityId: ISSUER_ENTITY_ID,
    rpEntityId: RP_ENTITY_ID,
    walletProviderEntityId: WALLET_PROVIDER_ENTITY_ID
  });

  app.decorate('trustAnchorKeys', {
    federationCertificateChain: [TRUST_ANCHOR_CERTIFICATE],
    federationPrivateJwk: generateFederationJwk('trust-anchor-federation-key'),
    subordinatePublicJwks: {
      issuer: publishedJwk(options.issuerFederationJwk, 'issuer'),
      rp: publishedJwk(options.rpFederationJwk, 'rp'),
      walletProvider: publishedJwk(
        options.walletProviderFederationJwk ?? generateFederationJwk('wallet-provider-signing-key'),
        'wallet-provider'
      )
    }
  });

  await app.register(fetchRoute);
  await app.ready();

  return app;
}

/** The keys a subordinate statement publishes, as a verifier reads them. */
function publishedKeys(statement: string): Array<{ kid?: string; x5c?: string[] }> {
  return (decodeJwt(statement) as unknown as { jwks: { keys: Array<{ kid?: string; x5c?: string[] }> } }).jwks.keys;
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

  it('adds an issuer metadata policy that excludes the WP_050a credential configuration', async () => {
    const app = await buildApp({
      issuerFederationJwk: generateFederationJwk('issuer-signing-key'),
      rpFederationJwk: generateFederationJwk('federation-key')
    });

    const response = await app.inject({ method: 'GET', url: `/fetch?sub=${encodeURIComponent(ISSUER_ENTITY_ID)}` });

    expect(response.statusCode).toBe(200);
    const payload = decodeJwt(response.body) as IssuerMetadataPolicyPayload;
    const policy = payload.metadata_policy?.openid_credential_issuer?.credential_configurations_supported;
    const subsetOf = policy?.subset_of;

    expect(policy?.essential).toBe(true);
    expect(Array.isArray(subsetOf), 'credential_configurations_supported policy must include subset_of').toBe(true);
    if (!Array.isArray(subsetOf)) {
      throw new Error('credential_configurations_supported policy subset_of is missing');
    }

    expect(subsetOf).toContain(METADATA_POLICY_ALLOWED_CREDENTIAL_CONFIGURATION_ID);
    expect(subsetOf).not.toContain(WP_050A_METADATA_POLICY_EXCLUDED_CREDENTIAL_CONFIGURATION_ID);

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

  it('returns a subordinate statement for the local wallet provider', async () => {
    const app = await buildApp({
      issuerFederationJwk: generateFederationJwk('issuer-signing-key'),
      rpFederationJwk: generateFederationJwk('federation-key')
    });

    const response = await app.inject({
      method: 'GET',
      url: `/fetch?sub=${encodeURIComponent(WALLET_PROVIDER_ENTITY_ID)}`
    });

    expect(response.statusCode).toBe(200);
    expect(decodeJwt(response.body).sub).toBe(WALLET_PROVIDER_ENTITY_ID);

    await app.close();
  });

  it.each([
    { entityId: ISSUER_ENTITY_ID, name: 'issuer', subjectChain: 'issuer' },
    { entityId: RP_ENTITY_ID, name: 'rp', subjectChain: 'rp' },
    { entityId: WALLET_PROVIDER_ENTITY_ID, name: 'wallet provider', subjectChain: 'wallet-provider' }
  ])('publishes a certificate chain beside every key in the $name statement', async ({ entityId, subjectChain }) => {
    const app = await buildApp({
      issuerFederationJwk: generateFederationJwk('issuer-signing-key'),
      rpFederationJwk: generateFederationJwk('federation-key')
    });

    const response = await app.inject({ method: 'GET', url: `/fetch?sub=${encodeURIComponent(entityId)}` });

    expect(response.statusCode).toBe(200);
    const keys = publishedKeys(response.body);

    // Two keys, two chains, and each is the chain for the key it accompanies:
    // the subject's own, and the Trust Anchor's for the key that signed the
    // statement. A wallet resolving a Trust Chain reads both here rather than
    // fetching two more Entity Configurations to find them.
    expect(keys).toHaveLength(2);
    expect(keys[0].x5c).toEqual(certificateChain(subjectChain));
    expect(keys[1].x5c).toEqual([TRUST_ANCHOR_CERTIFICATE]);

    await app.close();
  });

  it('does not add the issuer metadata policy to rp or wallet provider subordinate statements', async () => {
    const app = await buildApp({
      issuerFederationJwk: generateFederationJwk('issuer-signing-key'),
      rpFederationJwk: generateFederationJwk('federation-key')
    });

    const rpResponse = await app.inject({ method: 'GET', url: `/fetch?sub=${encodeURIComponent(RP_ENTITY_ID)}` });
    const walletProviderResponse = await app.inject({
      method: 'GET',
      url: `/fetch?sub=${encodeURIComponent(WALLET_PROVIDER_ENTITY_ID)}`
    });

    expect(rpResponse.statusCode).toBe(200);
    expect(walletProviderResponse.statusCode).toBe(200);
    expect((decodeJwt(rpResponse.body) as IssuerMetadataPolicyPayload).metadata_policy).toBeUndefined();
    expect((decodeJwt(walletProviderResponse.body) as IssuerMetadataPolicyPayload).metadata_policy).toBeUndefined();

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
