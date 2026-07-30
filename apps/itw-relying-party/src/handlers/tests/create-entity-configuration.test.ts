import { generateKeyPairSync } from 'node:crypto';

import Fastify from 'fastify';
import { createLocalJWKSet, decodeJwt, decodeProtectedHeader, jwtVerify } from 'jose';
import { describe, expect, it } from 'vitest';

import entityConfigurationRoute from '../../routes/entity-configuration.js';

import type { ActiveRpFault } from '../../faults/rp-fault-store.js';
import type { JWK } from 'jose';

const RP_BASE_URL = 'https://rp.example.org';
const TRUST_ANCHOR_URL = 'https://ta.example.org';
/** The type identifier lives in the Trust Anchor's namespace even though the Relying
 * Party issues the Trust Mark itself: the Trust Anchor owns the type and authorises the
 * Relying Party as its issuer through `trust_mark_issuers`. */
const TRUST_MARK_TYPE = `${TRUST_ANCHOR_URL}/trust_marks/presentation/relying_party`;

function generateJwk(kid: string, use: 'enc' | 'sig'): JWK & { kid: string } {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = privateKey.export({ format: 'jwk' }) as JWK;
  return { ...jwk, alg: use === 'sig' ? 'ES256' : 'ECDH-ES', kid, use };
}

function toPublicJwk(jwk: JWK): JWK {
  const { d, key_ops, ...publicJwk } = jwk;
  void d;
  void key_ops;
  return publicJwk;
}

/** Boots a minimal Fastify instance decorated only with what the route under test needs,
 * instead of the full app bootstrap (which requires real config.ini and key files on
 * disk). Mirrors the Trust Anchor's route tests. */
async function buildApp(options: { activeFault?: ActiveRpFault } = {}) {
  const app = Fastify();
  const federationJwk = generateJwk('rp-federation-key', 'sig');

  app.decorate('config', {
    BASE_URL: RP_BASE_URL,
    DATA_DIR: '/tmp/unused',
    IACA_X509: '',
    TRUST_ANCHOR_URL
  });

  app.decorate('jwks', {
    enc: {
      private: generateJwk('rp-encryption-key', 'enc'),
      public: toPublicJwk(generateJwk('rp-encryption-key', 'enc'))
    },
    federation: { private: federationJwk, public: toPublicJwk(federationJwk) },
    sig: { private: generateJwk('rp-signing-key', 'sig'), public: toPublicJwk(generateJwk('rp-signing-key', 'sig')) }
  });

  app.decorate('rpFaultStore', { getActive: () => options.activeFault });
  app.decorate('conformanceEventSink', { emit: async () => undefined });

  await app.register(entityConfigurationRoute);
  await app.ready();

  return { app, federationJwk };
}

type TrustMarkEntry = { trust_mark: string; trust_mark_type: string };

async function getTrustMarks(app: Awaited<ReturnType<typeof buildApp>>['app']): Promise<TrustMarkEntry[]> {
  const response = await app.inject({ method: 'GET', url: '/.well-known/openid-federation' });

  expect(response.statusCode).toBe(200);
  expect(response.headers['content-type']).toBe('application/entity-statement+jwt');

  return decodeJwt(response.body).trust_marks as TrustMarkEntry[];
}

describe('GET /.well-known/openid-federation', () => {
  it('publishes a Trust Mark the Relying Party issues about itself', async () => {
    const { app, federationJwk } = await buildApp();

    const [entry] = await getTrustMarks(app);

    expect(entry.trust_mark_type).toBe(TRUST_MARK_TYPE);

    const claims = decodeJwt(entry.trust_mark);
    expect(claims.iss, 'the Relying Party is both issuer and subject of its own Trust Mark').toBe(RP_BASE_URL);
    expect(claims.sub).toBe(RP_BASE_URL);
    expect(claims.trust_mark_type).toBe(TRUST_MARK_TYPE);

    const header = decodeProtectedHeader(entry.trust_mark);
    expect(header.typ).toBe('trust-mark+jwt');
    expect(header.kid).toBe(federationJwk.kid);

    await app.close();
  });

  it('signs the Trust Mark with the federation key the Relying Party publishes', async () => {
    const { app, federationJwk } = await buildApp();

    const [entry] = await getTrustMarks(app);

    // The wallet resolves the issuer's keys from the Relying Party Entity Configuration
    // it is already reading, so verification must succeed against exactly the federation
    // JWKS published there — and against nothing else.
    const federationJwks = createLocalJWKSet({ keys: [toPublicJwk(federationJwk)] });
    const { payload } = await jwtVerify(entry.trust_mark, federationJwks, {
      issuer: RP_BASE_URL,
      subject: RP_BASE_URL
    });

    expect(payload.trust_mark_type).toBe(TRUST_MARK_TYPE);

    await app.close();
  });

  it('signs the Trust Mark with an unpublished key under the invalid-trust-mark fault (WP_080)', async () => {
    const { app, federationJwk } = await buildApp({
      activeFault: {
        profile: { type: 'invalid-trust-mark' },
        scenarioId: 'WP_080'
      } as unknown as ActiveRpFault
    });

    const [entry] = await getTrustMarks(app);

    // The fault must stay invisible in the claims and the header: only the signature
    // distinguishes it, which is what isolates WP_080 from WP_087.
    const claims = decodeJwt(entry.trust_mark);
    expect(claims.iss).toBe(RP_BASE_URL);
    expect(claims.sub).toBe(RP_BASE_URL);
    expect(decodeProtectedHeader(entry.trust_mark).kid).toBe(federationJwk.kid);

    const federationJwks = createLocalJWKSet({ keys: [toPublicJwk(federationJwk)] });
    await expect(jwtVerify(entry.trust_mark, federationJwks)).rejects.toThrow();

    await app.close();
  });
});
