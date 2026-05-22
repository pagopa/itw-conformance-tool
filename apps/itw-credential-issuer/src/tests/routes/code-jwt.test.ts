import { afterEach, describe, expect, it, vi } from 'vitest';

const mocked = vi.hoisted(() => ({
  createAuthorizationCodeJwt: vi.fn()
}));

vi.mock('@itw-conformance-tool/issuer', async () => {
  const actual = await vi.importActual<typeof import('@itw-conformance-tool/issuer')>('@itw-conformance-tool/issuer');
  return {
    ...actual,
    CodeJwtService: class {
      createAuthorizationCodeJwt = mocked.createAuthorizationCodeJwt;
    }
  };
});

import codeJwtRoute from '../../routes/code-jwt.js';
import { buildRouteApp } from '../helpers/route-app.js';

describe('GET /code/jwt', () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it('returns HTML form post', async () => {
    mocked.createAuthorizationCodeJwt.mockResolvedValue({
      formPost: '<html><body>form</body></html>',
      redirectUri: 'https://wallet.example/cb'
    });

    const app = await buildRouteApp(codeJwtRoute);
    const response = await app.inject({
      method: 'GET',
      url: '/code/jwt?request_uri=urn:test'
    });

    expect(response.statusCode).toBe(200);
    expect(response.headers['content-type']).toContain('text/html');
    expect(response.body).toBe('<html><body>form</body></html>');

    await app.close();
  });
});
