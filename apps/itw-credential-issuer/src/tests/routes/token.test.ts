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
      token_type: 'Bearer'
    });

    const app = await buildRouteApp(tokenRoute);
    const response = await app.inject({
      method: 'POST',
      url: '/token',
      payload: 'code=abc&grant_type=authorization_code&redirect_uri=https%3A%2F%2Fclient.example',
      headers: { 'content-type': 'text/plain' }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      access_token: 'token',
      expires_in: 300,
      token_type: 'Bearer'
    });

    await app.close();
  });
});
