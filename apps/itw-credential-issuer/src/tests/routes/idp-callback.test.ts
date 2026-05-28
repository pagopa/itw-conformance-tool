import { SignJWT, exportJWK, generateKeyPair } from 'jose';
import { afterEach, describe, expect, it, vi } from 'vitest';

import idpCallbackRoute from '../../routes/idp-callback.js';
import { buildRouteApp } from '../helpers/route-app.js';

import type { FastifyInstance } from 'fastify';

interface TestApp extends FastifyInstance {
  parRepository: {
    getByMrtdAuthSession: ReturnType<typeof vi.fn>;
    update: ReturnType<typeof vi.fn>;
  };
}

const BASE_URL = 'http://localhost:3000';
const REDIRECT_URI = 'https://wallet.example/cb';
const STATE = 'test-state-abc';
const SESSION_ID = 'test-session-id';
const VAL_POP_NONCE = 'test-val-pop-nonce';

async function buildWalletKey() {
  const { privateKey, publicKey } = await generateKeyPair('ES256');
  const publicJwk = { ...(await exportJWK(publicKey)), alg: 'ES256', kid: 'wallet-test-key' };
  return { privateKey, publicJwk };
}

async function buildValPopNonceJwt(
  privateKey: CryptoKey,
  nonce: string,
  overrides: Record<string, unknown> = {}
): Promise<string> {
  return new SignJWT({ nonce, ...overrides })
    .setProtectedHeader({ alg: 'ES256', typ: 'mrtd-val-pop+jwt' })
    .setAudience(BASE_URL)
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(privateKey);
}

function buildVerifiedSession(walletPublicJwk: Record<string, unknown>, nonce = VAL_POP_NONCE) {
  return {
    mrtd_auth_session: SESSION_ID,
    status: 'verified',
    expires_at: Date.now() + 300_000,
    wallet_public_key: walletPublicJwk,
    mrtd_val_pop_nonce: nonce,
    mrtd_val_pop_nonce_consumed_at: undefined,
    auth_flow: 'l2plus',
    created_at: Math.floor(Date.now() / 1000),
    identity: {
      birthdate: '1990-12-12',
      family_name: 'Rossi',
      given_name: 'Mario',
      personal_administrative_number: 'RSSMRA90T12H501U',
      place_of_birth: { country: 'IT', locality: 'Roma', region: 'RM' }
    },
    mrtd_pop_jwt_nonce: 'some-init-nonce'
  };
}

function buildParEntry(session: ReturnType<typeof buildVerifiedSession>) {
  return {
    requestUri: 'urn:test:uri',
    clientId: 'wallet-client-1',
    expiresAt: Date.now() + 60_000,
    requestObject: JSON.stringify({
      client_id: 'wallet-client-1',
      redirect_uri: REDIRECT_URI,
      state: STATE,
      mrtd_auth_session: session
    })
  };
}

describe('GET /idp/callback', () => {
  let app: TestApp | undefined;

  afterEach(async () => {
    if (app) {
      await app.close();
      app = undefined;
    }
  });

  it('returns 400 if required query params are missing', async () => {
    app = (await buildRouteApp(idpCallbackRoute)) as TestApp;

    const response = await app.inject({ method: 'GET', url: '/idp/callback' });

    expect(response.statusCode).toBe(400);
  });

  it('returns 400 if mrtd_auth_session query param is missing', async () => {
    app = (await buildRouteApp(idpCallbackRoute)) as TestApp;

    const response = await app.inject({
      method: 'GET',
      url: '/idp/callback?mrtd_val_pop_nonce=sometoken'
    });

    expect(response.statusCode).toBe(400);
  });

  it('returns 400 if session is not found', async () => {
    app = (await buildRouteApp(idpCallbackRoute)) as TestApp;
    app.parRepository.getByMrtdAuthSession = vi.fn().mockResolvedValue(undefined);

    const response = await app.inject({
      method: 'GET',
      url: `/idp/callback?mrtd_auth_session=unknown&mrtd_val_pop_nonce=sometoken`
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({
      error: 'invalid_request',
      error_description: 'Session not found or expired'
    });
  });

  it('returns 400 if session is not in verified state (pending_mrtd_verify)', async () => {
    app = (await buildRouteApp(idpCallbackRoute)) as TestApp;
    const { publicJwk } = await buildWalletKey();
    const session = { ...buildVerifiedSession(publicJwk), status: 'pending_mrtd_verify' };
    app.parRepository.getByMrtdAuthSession = vi.fn().mockResolvedValue(buildParEntry(session));

    const response = await app.inject({
      method: 'GET',
      url: `/idp/callback?mrtd_auth_session=${SESSION_ID}&mrtd_val_pop_nonce=sometoken`
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({ error: 'invalid_request' });
  });

  it('returns 403 if session is already completed (anti-replay)', async () => {
    app = (await buildRouteApp(idpCallbackRoute)) as TestApp;
    const { publicJwk } = await buildWalletKey();
    const session = { ...buildVerifiedSession(publicJwk), status: 'completed' };
    app.parRepository.getByMrtdAuthSession = vi.fn().mockResolvedValue(buildParEntry(session));

    const response = await app.inject({
      method: 'GET',
      url: `/idp/callback?mrtd_auth_session=${SESSION_ID}&mrtd_val_pop_nonce=sometoken`
    });

    expect(response.statusCode).toBe(403);
    expect(response.json()).toMatchObject({ error: 'access_denied' });
  });

  it('returns 400 if session is expired', async () => {
    app = (await buildRouteApp(idpCallbackRoute)) as TestApp;
    const { publicJwk } = await buildWalletKey();
    const session = { ...buildVerifiedSession(publicJwk), expires_at: Date.now() - 1000 };
    app.parRepository.getByMrtdAuthSession = vi.fn().mockResolvedValue(buildParEntry(session));

    const response = await app.inject({
      method: 'GET',
      url: `/idp/callback?mrtd_auth_session=${SESSION_ID}&mrtd_val_pop_nonce=sometoken`
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({ error: 'invalid_request', error_description: 'Session expired' });
  });

  it('returns 403 if mrtd_val_pop_nonce has already been consumed (anti-replay)', async () => {
    app = (await buildRouteApp(idpCallbackRoute)) as TestApp;
    const { publicJwk } = await buildWalletKey();
    const session = {
      ...buildVerifiedSession(publicJwk),
      mrtd_val_pop_nonce_consumed_at: Math.floor(Date.now() / 1000) - 10
    };
    app.parRepository.getByMrtdAuthSession = vi.fn().mockResolvedValue(buildParEntry(session));

    const response = await app.inject({
      method: 'GET',
      url: `/idp/callback?mrtd_auth_session=${SESSION_ID}&mrtd_val_pop_nonce=sometoken`
    });

    expect(response.statusCode).toBe(403);
    expect(response.json()).toMatchObject({ error: 'access_denied', error_description: 'Nonce already consumed' });
  });

  it('returns 400 if wallet_public_key is missing from session', async () => {
    app = (await buildRouteApp(idpCallbackRoute)) as TestApp;
    const { publicJwk } = await buildWalletKey();
    const session = { ...buildVerifiedSession(publicJwk), wallet_public_key: undefined };
    app.parRepository.getByMrtdAuthSession = vi.fn().mockResolvedValue(buildParEntry(session));

    const response = await app.inject({
      method: 'GET',
      url: `/idp/callback?mrtd_auth_session=${SESSION_ID}&mrtd_val_pop_nonce=sometoken`
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({
      error: 'invalid_request',
      error_description: 'Missing wallet public key in session'
    });
  });

  it('returns 400 if mrtd_val_pop_nonce JWT signature is invalid', async () => {
    app = (await buildRouteApp(idpCallbackRoute)) as TestApp;
    const { privateKey: _otherKey, publicJwk: otherPublicJwk } = await buildWalletKey();
    const { privateKey: wrongKey } = await buildWalletKey();
    const session = buildVerifiedSession(otherPublicJwk);
    app.parRepository.getByMrtdAuthSession = vi.fn().mockResolvedValue(buildParEntry(session));

    // Sign with a different key than the one stored in session
    const jwt = await buildValPopNonceJwt(wrongKey, VAL_POP_NONCE);

    const response = await app.inject({
      method: 'GET',
      url: `/idp/callback?mrtd_auth_session=${SESSION_ID}&mrtd_val_pop_nonce=${encodeURIComponent(jwt)}`
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({
      error: 'invalid_request',
      error_description: 'Invalid mrtd_val_pop_nonce JWT'
    });
  });

  it('returns 400 if mrtd_val_pop_nonce JWT is not a valid JWT', async () => {
    app = (await buildRouteApp(idpCallbackRoute)) as TestApp;
    const { publicJwk } = await buildWalletKey();
    const session = buildVerifiedSession(publicJwk);
    app.parRepository.getByMrtdAuthSession = vi.fn().mockResolvedValue(buildParEntry(session));

    const response = await app.inject({
      method: 'GET',
      url: `/idp/callback?mrtd_auth_session=${SESSION_ID}&mrtd_val_pop_nonce=not.a.valid.jwt`
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({
      error: 'invalid_request',
      error_description: 'Invalid mrtd_val_pop_nonce JWT'
    });
  });

  it('returns 400 if JWT is missing exp claim', async () => {
    app = (await buildRouteApp(idpCallbackRoute)) as TestApp;
    const { privateKey, publicJwk } = await buildWalletKey();
    const session = buildVerifiedSession(publicJwk);
    app.parRepository.getByMrtdAuthSession = vi.fn().mockResolvedValue(buildParEntry(session));

    // Build JWT without exp
    const jwt = await new SignJWT({ nonce: VAL_POP_NONCE })
      .setProtectedHeader({ alg: 'ES256' })
      .setAudience(BASE_URL)
      .setIssuedAt()
      .sign(privateKey);

    const response = await app.inject({
      method: 'GET',
      url: `/idp/callback?mrtd_auth_session=${SESSION_ID}&mrtd_val_pop_nonce=${encodeURIComponent(jwt)}`
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({
      error: 'invalid_request',
      error_description: 'Invalid mrtd_val_pop_nonce JWT'
    });
  });

  it('returns 400 if JWT is missing iat claim', async () => {
    app = (await buildRouteApp(idpCallbackRoute)) as TestApp;
    const { privateKey, publicJwk } = await buildWalletKey();
    const session = buildVerifiedSession(publicJwk);
    app.parRepository.getByMrtdAuthSession = vi.fn().mockResolvedValue(buildParEntry(session));

    // Build JWT without iat (use SignJWT without setIssuedAt)
    const jwt = await new SignJWT({ nonce: VAL_POP_NONCE })
      .setProtectedHeader({ alg: 'ES256' })
      .setAudience(BASE_URL)
      .setExpirationTime('5m')
      .sign(privateKey);

    const response = await app.inject({
      method: 'GET',
      url: `/idp/callback?mrtd_auth_session=${SESSION_ID}&mrtd_val_pop_nonce=${encodeURIComponent(jwt)}`
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({
      error: 'invalid_request',
      error_description: 'Invalid mrtd_val_pop_nonce JWT'
    });
  });

  it('returns 400 if nonce in JWT does not match session mrtd_val_pop_nonce (FR-61)', async () => {
    app = (await buildRouteApp(idpCallbackRoute)) as TestApp;
    const { privateKey, publicJwk } = await buildWalletKey();
    const session = buildVerifiedSession(publicJwk, 'expected-nonce');
    app.parRepository.getByMrtdAuthSession = vi.fn().mockResolvedValue(buildParEntry(session));

    // JWT contains a different nonce
    const jwt = await buildValPopNonceJwt(privateKey, 'wrong-nonce');

    const response = await app.inject({
      method: 'GET',
      url: `/idp/callback?mrtd_auth_session=${SESSION_ID}&mrtd_val_pop_nonce=${encodeURIComponent(jwt)}`
    });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toMatchObject({
      error: 'invalid_request',
      error_description: 'mrtd_val_pop_nonce does not match issued nonce'
    });
  });

  it('returns 302 with code, state and iss on happy path (FR-63)', async () => {
    app = (await buildRouteApp(idpCallbackRoute)) as TestApp;
    const { privateKey, publicJwk } = await buildWalletKey();
    const session = buildVerifiedSession(publicJwk);
    app.parRepository.getByMrtdAuthSession = vi.fn().mockResolvedValue(buildParEntry(session));
    app.parRepository.update = vi.fn().mockResolvedValue(undefined);

    const jwt = await buildValPopNonceJwt(privateKey, VAL_POP_NONCE);

    const response = await app.inject({
      method: 'GET',
      url: `/idp/callback?mrtd_auth_session=${SESSION_ID}&mrtd_val_pop_nonce=${encodeURIComponent(jwt)}`
    });

    expect(response.statusCode).toBe(302);
    const location = new URL(response.headers['location'] as string);
    expect(location.origin + location.pathname).toBe(REDIRECT_URI);
    expect(location.searchParams.get('code')).toBeTruthy();
    expect(location.searchParams.get('state')).toBe(STATE);
    expect(location.searchParams.get('iss')).toBe(BASE_URL);
  });

  it('persists the authorization code and marks the session as completed on success', async () => {
    app = (await buildRouteApp(idpCallbackRoute)) as TestApp;
    const { privateKey, publicJwk } = await buildWalletKey();
    const session = buildVerifiedSession(publicJwk);
    app.parRepository.getByMrtdAuthSession = vi.fn().mockResolvedValue(buildParEntry(session));
    app.parRepository.update = vi.fn().mockResolvedValue(undefined);

    const jwt = await buildValPopNonceJwt(privateKey, VAL_POP_NONCE);

    await app.inject({
      method: 'GET',
      url: `/idp/callback?mrtd_auth_session=${SESSION_ID}&mrtd_val_pop_nonce=${encodeURIComponent(jwt)}`
    });

    expect(app.parRepository.update).toHaveBeenCalledOnce();
    const [, updateData] = app.parRepository.update.mock.calls[0];
    const updatedParRequest = JSON.parse(updateData.requestObject);
    expect(updatedParRequest.code).toBeTruthy();
    expect(updatedParRequest.code_expires_at).toBeTypeOf('number');
    expect(updatedParRequest.mrtd_auth_session.status).toBe('completed');
    expect(updatedParRequest.mrtd_auth_session.mrtd_val_pop_nonce_consumed_at).toBeTypeOf('number');
  });
});
