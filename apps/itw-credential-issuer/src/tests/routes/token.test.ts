import { InvalidGrantError } from '@itw-conformance-tool/issuer';
import { Oauth2Error } from '@pagopa/io-wallet-oauth2';
import { afterEach, describe, expect, it, vi } from 'vitest';

const mocked = vi.hoisted(() => ({
  createAccessToken: vi.fn()
}));

vi.mock('@itw-conformance-tool/issuer', async () => {
  const actual = await vi.importActual<typeof import('@itw-conformance-tool/issuer')>('@itw-conformance-tool/issuer');
  return {
    ...actual,
    TokenService: class {
      createAccessToken = mocked.createAccessToken;
    }
  };
});

import tokenRoute from '../../routes/token.js';
import { buildRouteApp } from '../helpers/route-app.js';

describe('POST /token', () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it('returns access token payload from TokenService', async () => {
    mocked.createAccessToken.mockResolvedValue({
      access_token: 'token',
      expires_in: 300,
      token_type: 'DPoP'
    });

    const app = await buildRouteApp(tokenRoute);
    const response = await app.inject({
      method: 'POST',
      url: '/token',
      payload:
        'code=abc&code_verifier=verifier123&grant_type=authorization_code&redirect_uri=https%3A%2F%2Fclient.example',
      headers: { 'content-type': 'text/plain', dpop: 'dpop-jwt' }
    });

    expect(response.statusCode).toBe(200);
    expect(response.headers['cache-control']).toBe('no-store');
    expect(response.headers.pragma).toBe('no-cache');
    expect(response.json()).toEqual({
      access_token: 'token',
      expires_in: 300,
      token_type: 'DPoP'
    });

    await app.close();
  });

  it('returns invalid_grant with no-cache headers', async () => {
    mocked.createAccessToken.mockRejectedValue(new InvalidGrantError('code expired'));

    const app = await buildRouteApp(tokenRoute);
    const response = await app.inject({
      method: 'POST',
      url: '/token',
      payload:
        'code=abc&code_verifier=verifier123&grant_type=authorization_code&redirect_uri=https%3A%2F%2Fclient.example',
      headers: { 'content-type': 'text/plain', dpop: 'dpop-jwt' }
    });

    expect(response.statusCode).toBe(400);
    expect(response.headers['cache-control']).toBe('no-store');
    expect(response.headers.pragma).toBe('no-cache');
    expect(response.json()).toEqual({
      error: 'invalid_grant',
      error_description: 'code expired'
    });

    await app.close();
  });

  it('returns invalid_request for oauth2 parsing/verification errors', async () => {
    mocked.createAccessToken.mockRejectedValue(new Oauth2Error('missing OAuth-Client-Attestation header'));

    const app = await buildRouteApp(tokenRoute);
    const response = await app.inject({
      method: 'POST',
      url: '/token',
      payload:
        'code=abc&code_verifier=verifier123&grant_type=authorization_code&redirect_uri=https%3A%2F%2Fclient.example',
      headers: { 'content-type': 'text/plain', dpop: 'dpop-jwt' }
    });

    expect(response.statusCode).toBe(400);
    expect(response.headers['cache-control']).toBe('no-store');
    expect(response.headers.pragma).toBe('no-cache');
    expect(response.json()).toEqual({
      error: 'invalid_request',
      error_description: 'missing OAuth-Client-Attestation header'
    });

    await app.close();
  });
});
