import { afterEach, describe, expect, it, vi } from 'vitest';

const mocked = vi.hoisted(() => ({
  getEntityConfiguration: vi.fn()
}));

vi.mock('@itw-conformance-tool/issuer', async () => {
  const actual = await vi.importActual<typeof import('@itw-conformance-tool/issuer')>('@itw-conformance-tool/issuer');
  return {
    ...actual,
    FederationService: class {
      getEntityConfiguration = mocked.getEntityConfiguration;
    }
  };
});

import federationRoute from '../../routes/federation.js';
import { buildRouteApp } from '../helpers/route-app.js';

describe('GET /.well-known/openid-federation', () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it('returns entity statement JWT', async () => {
    mocked.getEntityConfiguration.mockResolvedValue('header.payload.signature');

    const app = await buildRouteApp(federationRoute);
    const response = await app.inject({
      method: 'GET',
      url: '/.well-known/openid-federation'
    });

    expect(response.statusCode).toBe(200);
    expect(response.headers['content-type']).toContain('application/entity-statement+jwt');
    expect(response.body).toBe('header.payload.signature');

    await app.close();
  });
});
