import { afterEach, describe, expect, it, vi } from 'vitest';

const mocked = vi.hoisted(() => ({
  authorize: vi.fn()
}));

vi.mock('@itw-conformance-tool/issuer', async () => {
  const actual = await vi.importActual<typeof import('@itw-conformance-tool/issuer')>('@itw-conformance-tool/issuer');
  return {
    ...actual,
    AuthorizationService: class {
      authorize = mocked.authorize;
    }
  };
});

import authorizeRoute from '../../routes/authorize.js';
import { buildRouteApp } from '../helpers/route-app.js';

describe('GET /authorize', () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it('returns redirect when authorization succeeds with redirect result', async () => {
    mocked.authorize.mockResolvedValue({
      kind: 'redirect',
      location: 'https://wallet.example/cb?code=abc'
    });

    const app = await buildRouteApp(authorizeRoute);
    const response = await app.inject({
      method: 'GET',
      url: '/authorize?client_id=client&request_uri=urn:test'
    });

    expect(response.statusCode).toBe(302);
    expect(response.headers.location).toBe('https://wallet.example/cb?code=abc');

    await app.close();
  });
});
