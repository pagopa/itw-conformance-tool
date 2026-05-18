import { afterEach, describe, expect, it, vi } from 'vitest';

const mocked = vi.hoisted(() => ({
  getStatusListJwt: vi.fn()
}));

vi.mock('@itw-conformance-tool/issuer', async () => {
  const actual = await vi.importActual<typeof import('@itw-conformance-tool/issuer')>('@itw-conformance-tool/issuer');
  return {
    ...actual,
    StatusListService: class {
      getStatusListJwt = mocked.getStatusListJwt;
    }
  };
});

import statusListRoute from '../../routes/statuslist.js';
import { buildRouteApp } from '../helpers/route-app.js';

describe('GET /statuslist/1', () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it('returns status list JWT', async () => {
    mocked.getStatusListJwt.mockResolvedValue('status.header.payload');

    const app = await buildRouteApp(statusListRoute);
    const response = await app.inject({
      method: 'GET',
      url: '/statuslist/1'
    });

    expect(response.statusCode).toBe(200);
    expect(response.headers['content-type']).toContain('application/statuslist+jwt');
    expect(response.body).toBe('status.header.payload');

    await app.close();
  });
});
