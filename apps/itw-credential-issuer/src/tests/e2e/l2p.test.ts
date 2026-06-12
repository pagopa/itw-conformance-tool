import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import Fastify from 'fastify';
import { SignJWT, decodeJwt, exportJWK, generateKeyPair } from 'jose';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { generateIaca, generateJwks } from '../../crypto/auto-keygen.js';
import conformanceHooks from '../../hooks/conformance.js';
import configPlugin from '../../plugins/config.js';
import dbPlugin from '../../plugins/db.js';
import corsPlugin, { autoConfig as corsConfig } from '../../plugins/external/cors.js';
import formbodyPlugin from '../../plugins/external/formbody.js';
import helmetPlugin, { autoConfig as helmetConfig } from '../../plugins/external/helmet.js';
import rateLimitPlugin, { autoConfig as rateLimitConfig } from '../../plugins/external/rate-limit.js';
import sensiblePlugin from '../../plugins/external/sensible.js';
import keysPlugin from '../../plugins/keys.js';
import authorizeRoute from '../../routes/authorize.js';
import edocProofRoute from '../../routes/edoc-proof.js';
import edocRoute from '../../routes/edoc.js';
import idpCallbackRoute from '../../routes/idp-callback.js';
import mockIdpRoute from '../../routes/mock-idp.js';

const REQUEST_URI = 'urn:ietf:params:oauth:request_uri:e2e-test';
const CLIENT_ID = 'test-e2e-wallet-client';
const REDIRECT_URI = 'https://example.com/callback';
const STATE = 'e2e-state-123';
const BASE_URL = 'http://localhost:3000';

const ENV_KEYS = ['DATA_DIR', 'PORT', 'HOST', 'DB_CLEANUP_INTERVAL_MS', 'AUTH_FLOW'] as const;

function getRequiredSearchParam(url: URL, param: string): string {
  const value = url.searchParams.get(param);
  if (!value) {
    throw new Error(`Missing '${param}' query parameter`);
  }
  return value;
}

async function setupKeyMaterial(): Promise<string> {
  const rootDir = mkdtempSync(path.join(tmpdir(), 'issuer-e2e-'));
  const issuerDir = path.join(rootDir, 'issuer');
  mkdirSync(issuerDir);
  const [jwksJson, iaca] = await Promise.all([generateJwks(), generateIaca()]);
  writeFileSync(path.join(issuerDir, 'signing-keys.jwks.json'), jwksJson);
  writeFileSync(path.join(issuerDir, 'iaca-cert.pem'), iaca.certPem);
  writeFileSync(path.join(issuerDir, 'iaca-key.pem'), iaca.keyPem);
  return rootDir;
}

async function createApp(authFlow: 'direct' | 'l2plus' | 'l3') {
  process.env.DATA_DIR = await setupKeyMaterial();
  process.env.DB_CLEANUP_INTERVAL_MS = '999999';
  process.env.AUTH_FLOW = authFlow;

  const app = Fastify({ logger: false });

  await app.register(configPlugin);
  await app.register(dbPlugin);
  await app.register(keysPlugin);
  await app.register(conformanceHooks);
  await app.register(corsPlugin, corsConfig);
  await app.register(helmetPlugin, helmetConfig);
  await app.register(formbodyPlugin);
  await app.register(rateLimitPlugin, rateLimitConfig);
  await app.register(sensiblePlugin);

  await app.register(authorizeRoute);
  await app.register(mockIdpRoute);
  await app.register(edocRoute);
  await app.register(edocProofRoute);
  await app.register(idpCallbackRoute);

  await app.ready();
  return app;
}

function makePidParRequestObject() {
  return JSON.stringify({
    authorization_details: [
      { credential_configuration_id: 'dc_sd_jwt_PersonIdentificationData', type: 'openid_credential' }
    ],
    client_id: CLIENT_ID,
    code_challenge: 'dGVzdC1jaGFsbGVuZ2U',
    code_challenge_method: 'S256',
    id: 'par-e2e-1',
    redirect_uri: REDIRECT_URI,
    request_uri: REQUEST_URI,
    response_type: 'code',
    state: STATE
  });
}

async function buildWalletKeyMaterial(audience: string) {
  const { privateKey, publicKey } = await generateKeyPair('ES256');
  const walletPublicJwk = { ...(await exportJWK(publicKey)), alg: 'ES256', kid: 'wallet-e2e-key' };

  const attestationJwt = await new SignJWT({ cnf: { jwk: walletPublicJwk } })
    .setProtectedHeader({ alg: 'ES256', jwk: walletPublicJwk, typ: 'wallet-attestation+jwt' })
    .setIssuer('https://wallet-provider.example.it')
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(privateKey);

  const attestationPopJwt = await new SignJWT({ iss: CLIENT_ID })
    .setProtectedHeader({ alg: 'ES256', typ: 'oauth-client-attestation-pop+jwt' })
    .setJti('l2p-pop-init')
    .setAudience(audience)
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(privateKey);

  return { attestationJwt, attestationPopJwt, privateKey, walletPublicJwk };
}

async function buildWalletAttestationJwts(audience: string) {
  const { attestationJwt, attestationPopJwt } = await buildWalletKeyMaterial(audience);
  return { attestationJwt, attestationPopJwt };
}

/** Runs the full L2+ flow up to and including /edoc-proof/verify. Returns everything
 * the wallet needs to call /idp/callback. */
async function runL2PlusUpToVerify(app: Awaited<ReturnType<typeof createApp>>) {
  // /authorize → /idp/authorize
  await app.inject({
    method: 'GET',
    url: `/authorize?client_id=${CLIENT_ID}&request_uri=${encodeURIComponent(REQUEST_URI)}`
  });
  const idpResponse = await app.inject({
    method: 'GET',
    url: `/idp/authorize?request_uri=${encodeURIComponent(REQUEST_URI)}`
  });
  const walletLocation = new URL(idpResponse.headers.location as string);
  const challengeInfoJwt = getRequiredSearchParam(walletLocation, 'challenge_info');
  const challengePayload = decodeJwt(challengeInfoJwt) as Record<string, unknown>;
  const mrtdAuthSession = challengePayload['mrtd_auth_session'] as string;
  const mrtdPopJwtNonce = challengePayload['mrtd_pop_jwt_nonce'] as string;

  // /edoc-proof/init — keep the same private key for the whole flow
  const { attestationJwt, attestationPopJwt, privateKey, walletPublicJwk } = await buildWalletKeyMaterial(BASE_URL);
  const initResponse = await app.inject({
    method: 'POST',
    url: '/edoc-proof/init',
    headers: {
      'content-type': 'application/json',
      'oauth-client-attestation': attestationJwt,
      'oauth-client-attestation-pop': attestationPopJwt
    },
    payload: JSON.stringify({ mrtd_auth_session: mrtdAuthSession, mrtd_pop_jwt_nonce: mrtdPopJwtNonce })
  });
  const popPayload = decodeJwt(initResponse.body) as Record<string, unknown>;
  const mrtdPopNonce = popPayload['mrtd_pop_nonce'] as string;

  // Build mrtd_validation_jwt (fake CIE data, valid Base64)
  // The wallet uses the same key pair throughout the L2+ flow.
  const fakeB64 = Buffer.from('fake').toString('base64');
  const att2 = await new SignJWT({ cnf: { jwk: walletPublicJwk } })
    .setProtectedHeader({ alg: 'ES256', jwk: walletPublicJwk, typ: 'wallet-attestation+jwt' })
    .setIssuer('https://wallet-provider.example.it')
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(privateKey);
  const pop2 = await new SignJWT({ iss: CLIENT_ID })
    .setProtectedHeader({ alg: 'ES256', typ: 'oauth-client-attestation-pop+jwt' })
    .setJti('l2p-pop-verify')
    .setAudience(BASE_URL)
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(privateKey);
  const validationJwt = await new SignJWT({
    aud: BASE_URL,
    document_type: 'cie',
    ias: { challenge_signed: fakeB64, ias_pk: fakeB64, sod_ias: fakeB64 },
    iss: CLIENT_ID,
    mrtd: { dg1: fakeB64, dg11: fakeB64, sod_mrtd: fakeB64 }
  })
    .setProtectedHeader({ alg: 'ES256', kid: walletPublicJwk.kid, typ: 'mrtd-ias+jwt' })
    .setIssuedAt()
    .setExpirationTime('10m')
    .sign(privateKey);

  // /edoc-proof/verify
  const verifyResponse = await app.inject({
    method: 'POST',
    url: '/edoc-proof/verify',
    headers: {
      'content-type': 'application/json',
      'oauth-client-attestation': att2,
      'oauth-client-attestation-pop': pop2
    },
    payload: JSON.stringify({
      mrtd_auth_session: mrtdAuthSession,
      mrtd_pop_nonce: mrtdPopNonce,
      mrtd_validation_jwt: validationJwt
    })
  });

  const verifyBody = verifyResponse.json() as Record<string, unknown>;
  return {
    mrtdAuthSession,
    mrtdValPopNonce: verifyBody['mrtd_val_pop_nonce'] as string,
    privateKey
  };
}

describe('E2E: L2+ partial path (POST /edoc-proof/init)', () => {
  let app: Awaited<ReturnType<typeof createApp>>;

  beforeEach(async () => {
    for (const key of ENV_KEYS) delete process.env[key];
    app = await createApp('l2plus');
    await app.parRepository.insert({
      clientId: CLIENT_ID,
      expiresAt: Date.now() + 60_000,
      requestObject: makePidParRequestObject(),
      requestUri: REQUEST_URI
    });
  });

  afterEach(async () => {
    await app.close();
    for (const key of ENV_KEYS) delete process.env[key];
  });

  it('routes through mock IdP, creates MRTD session with challenge_info, and init returns signed PoP Response JWT', async () => {
    // Step 1: /authorize redirects to /idp/authorize
    const authResponse = await app.inject({
      method: 'GET',
      url: `/authorize?client_id=${CLIENT_ID}&request_uri=${encodeURIComponent(REQUEST_URI)}`
    });

    expect(authResponse.statusCode).toBe(302);
    const idpLocation = new URL(authResponse.headers.location as string);
    expect(idpLocation.pathname).toBe('/idp/authorize');

    // Step 2: /idp/authorize creates MRTD session and redirects with challenge_info
    const idpResponse = await app.inject({
      method: 'GET',
      url: idpLocation.pathname + idpLocation.search
    });

    expect(idpResponse.statusCode).toBe(302);
    const walletLocation = new URL(idpResponse.headers.location as string);
    expect(walletLocation.origin + walletLocation.pathname).toBe(REDIRECT_URI);
    expect(walletLocation.searchParams.get('state')).toBe(STATE);

    const challengeInfoJwt = getRequiredSearchParam(walletLocation, 'challenge_info');
    expect(challengeInfoJwt).toBeTruthy();
    expect(walletLocation.searchParams.get('code')).toBeNull();

    // Decode challenge_info JWT (wallet decodes it to extract session details)
    const challengePayload = decodeJwt(challengeInfoJwt) as Record<string, unknown>;
    expect(challengePayload['status']).toBe('require_interaction');
    expect(challengePayload['type']).toBe('mrtd+ias');
    expect(challengePayload['htm']).toBe('POST');
    expect(challengePayload['htu']).toBe(`${BASE_URL}/edoc-proof/init`);

    const mrtdAuthSession = challengePayload['mrtd_auth_session'] as string;
    const mrtdPopJwtNonce = challengePayload['mrtd_pop_jwt_nonce'] as string;
    expect(typeof mrtdAuthSession).toBe('string');
    expect(typeof mrtdPopJwtNonce).toBe('string');

    // Step 3: Wallet calls /edoc-proof/init with wallet attestation headers
    const { attestationJwt, attestationPopJwt } = await buildWalletAttestationJwts(BASE_URL);
    const initResponse = await app.inject({
      method: 'POST',
      url: '/edoc-proof/init',
      headers: {
        'content-type': 'application/json',
        'oauth-client-attestation': attestationJwt,
        'oauth-client-attestation-pop': attestationPopJwt
      },
      payload: JSON.stringify({ mrtd_auth_session: mrtdAuthSession, mrtd_pop_jwt_nonce: mrtdPopJwtNonce })
    });

    expect(initResponse.statusCode).toBe(202);
    expect(initResponse.headers['content-type']).toContain('application/jwt');

    // Verify the MRTD PoP Response JWT structure
    const popPayload = decodeJwt(initResponse.body) as Record<string, unknown>;
    expect(popPayload['iss']).toBe(BASE_URL);
    expect(popPayload['aud']).toBe(CLIENT_ID);
    expect(popPayload['htm']).toBe('POST');
    expect(popPayload['htu']).toBe(`${BASE_URL}/edoc-proof/verify`);
    expect(typeof popPayload['challenge']).toBe('string');
    expect(typeof popPayload['mrtd_pop_nonce']).toBe('string');
    expect(typeof popPayload['iat']).toBe('number');
    expect(typeof popPayload['exp']).toBe('number');
  });

  it('returns 403 access_denied when /edoc-proof/init is called twice (replay protection)', async () => {
    await app.inject({
      method: 'GET',
      url: `/authorize?client_id=${CLIENT_ID}&request_uri=${encodeURIComponent(REQUEST_URI)}`
    });
    const idpResponse = await app.inject({
      method: 'GET',
      url: `/idp/authorize?request_uri=${encodeURIComponent(REQUEST_URI)}`
    });
    const walletLocation = new URL(idpResponse.headers.location as string);
    const challengeInfoJwt = getRequiredSearchParam(walletLocation, 'challenge_info');
    const challengePayload = decodeJwt(challengeInfoJwt) as Record<string, unknown>;
    const mrtdAuthSession = challengePayload['mrtd_auth_session'] as string;
    const mrtdPopJwtNonce = challengePayload['mrtd_pop_jwt_nonce'] as string;

    const { attestationJwt, attestationPopJwt } = await buildWalletAttestationJwts(BASE_URL);
    const body = JSON.stringify({ mrtd_auth_session: mrtdAuthSession, mrtd_pop_jwt_nonce: mrtdPopJwtNonce });
    const headers = {
      'content-type': 'application/json',
      'oauth-client-attestation': attestationJwt,
      'oauth-client-attestation-pop': attestationPopJwt
    };

    // First call succeeds
    const first = await app.inject({ method: 'POST', url: '/edoc-proof/init', headers, payload: body });
    expect(first.statusCode).toBe(202);

    // Second call is rejected as replay (new attestation PoP needed since aud check still passes,
    // but the session is now in pending_mrtd_verify state)
    const { attestationJwt: att2, attestationPopJwt: pop2 } = await buildWalletAttestationJwts(BASE_URL);
    const second = await app.inject({
      method: 'POST',
      url: '/edoc-proof/init',
      headers: {
        'content-type': 'application/json',
        'oauth-client-attestation': att2,
        'oauth-client-attestation-pop': pop2
      },
      payload: body
    });
    expect(second.statusCode).toBe(403);
    expect(second.json()['error']).toBe('access_denied');
  });

  it('returns 401 invalid_client when wallet attestation PoP signature is invalid', async () => {
    await app.inject({
      method: 'GET',
      url: `/authorize?client_id=${CLIENT_ID}&request_uri=${encodeURIComponent(REQUEST_URI)}`
    });
    const idpResponse = await app.inject({
      method: 'GET',
      url: `/idp/authorize?request_uri=${encodeURIComponent(REQUEST_URI)}`
    });
    const walletLocation = new URL(idpResponse.headers.location as string);
    const challengePayload = decodeJwt(getRequiredSearchParam(walletLocation, 'challenge_info')) as Record<
      string,
      unknown
    >;

    const initResponse = await app.inject({
      method: 'POST',
      url: '/edoc-proof/init',
      headers: {
        'content-type': 'application/json',
        'oauth-client-attestation': 'not.a.valid.jwt',
        'oauth-client-attestation-pop': 'not.a.valid.pop'
      },
      payload: JSON.stringify({
        mrtd_auth_session: challengePayload['mrtd_auth_session'],
        mrtd_pop_jwt_nonce: challengePayload['mrtd_pop_jwt_nonce']
      })
    });

    expect(initResponse.statusCode).toBe(401);
    expect(initResponse.json()['error']).toBe('invalid_client');
  });
});

describe('E2E: L2+ full path (GET /idp/callback)', () => {
  let app: Awaited<ReturnType<typeof createApp>>;

  beforeEach(async () => {
    for (const key of ENV_KEYS) delete process.env[key];
    app = await createApp('l2plus');
    await app.parRepository.insert({
      clientId: CLIENT_ID,
      expiresAt: Date.now() + 60_000,
      requestObject: makePidParRequestObject(),
      requestUri: REQUEST_URI
    });
  });

  afterEach(async () => {
    await app.close();
    for (const key of ENV_KEYS) delete process.env[key];
  });

  it('completes the full L2+ flow and issues an authorization code via 302 redirect', async () => {
    const { mrtdAuthSession, mrtdValPopNonce, privateKey } = await runL2PlusUpToVerify(app);

    // Wallet signs the mrtd_val_pop_nonce JWT with its own key (same as stored in session)
    const valPopNonceJwt = await new SignJWT({ nonce: mrtdValPopNonce })
      .setProtectedHeader({ alg: 'ES256', typ: 'mrtd-val-pop+jwt' })
      .setAudience(BASE_URL)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);

    const callbackResponse = await app.inject({
      method: 'GET',
      url: `/idp/callback?mrtd_auth_session=${mrtdAuthSession}&mrtd_val_pop_nonce=${encodeURIComponent(valPopNonceJwt)}`
    });

    expect(callbackResponse.statusCode).toBe(302);
    const location = new URL(callbackResponse.headers['location'] as string);
    expect(location.origin + location.pathname).toBe(REDIRECT_URI);
    expect(location.searchParams.get('code')).toBeTruthy();
    expect(location.searchParams.get('state')).toBe(STATE);
    expect(location.searchParams.get('iss')).toBe(BASE_URL);
  });

  it('returns 403 access_denied when /idp/callback is called twice with the same nonce (replay protection)', async () => {
    const { mrtdAuthSession, mrtdValPopNonce, privateKey } = await runL2PlusUpToVerify(app);

    const valPopNonceJwt = await new SignJWT({ nonce: mrtdValPopNonce })
      .setProtectedHeader({ alg: 'ES256', typ: 'mrtd-val-pop+jwt' })
      .setAudience(BASE_URL)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);

    const url = `/idp/callback?mrtd_auth_session=${mrtdAuthSession}&mrtd_val_pop_nonce=${encodeURIComponent(valPopNonceJwt)}`;

    const first = await app.inject({ method: 'GET', url });
    expect(first.statusCode).toBe(302);

    const second = await app.inject({ method: 'GET', url });
    expect(second.statusCode).toBe(403);
    expect(second.json()['error']).toBe('access_denied');
  });

  it('returns 400 when the mrtd_val_pop_nonce JWT contains the wrong nonce (FR-61)', async () => {
    const { mrtdAuthSession, privateKey } = await runL2PlusUpToVerify(app);

    // JWT signed correctly but with the wrong nonce value
    const valPopNonceJwt = await new SignJWT({ nonce: 'this-is-not-the-right-nonce' })
      .setProtectedHeader({ alg: 'ES256', typ: 'mrtd-val-pop+jwt' })
      .setAudience(BASE_URL)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);

    const callbackResponse = await app.inject({
      method: 'GET',
      url: `/idp/callback?mrtd_auth_session=${mrtdAuthSession}&mrtd_val_pop_nonce=${encodeURIComponent(valPopNonceJwt)}`
    });

    expect(callbackResponse.statusCode).toBe(400);
    expect(callbackResponse.json()).toMatchObject({
      error: 'invalid_request',
      error_description: 'mrtd_val_pop_nonce does not match issued nonce'
    });
  });

  it('returns 400 when the mrtd_val_pop_nonce JWT is signed with a different key', async () => {
    const { mrtdAuthSession, mrtdValPopNonce } = await runL2PlusUpToVerify(app);

    // Sign with a fresh unrelated key pair — session holds the original wallet key
    const { privateKey: wrongKey } = await generateKeyPair('ES256');
    const valPopNonceJwt = await new SignJWT({ nonce: mrtdValPopNonce })
      .setProtectedHeader({ alg: 'ES256', typ: 'mrtd-val-pop+jwt' })
      .setAudience(BASE_URL)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(wrongKey);

    const callbackResponse = await app.inject({
      method: 'GET',
      url: `/idp/callback?mrtd_auth_session=${mrtdAuthSession}&mrtd_val_pop_nonce=${encodeURIComponent(valPopNonceJwt)}`
    });

    expect(callbackResponse.statusCode).toBe(400);
    expect(callbackResponse.json()).toMatchObject({
      error: 'invalid_request',
      error_description: 'Invalid mrtd_val_pop_nonce JWT'
    });
  });
});
