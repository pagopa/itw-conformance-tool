import { afterEach, describe, expect, it, vi } from 'vitest';

const mocked = vi.hoisted(() => ({
  parseAndStore: vi.fn()
}));

vi.mock('@itw-conformance-tool/issuer', async () => {
  const actual = await vi.importActual<typeof import('@itw-conformance-tool/issuer')>('@itw-conformance-tool/issuer');
  return {
    ...actual,
    PARService: class {
      parseAndStore = mocked.parseAndStore;
    }
  };
});

import parRoute from '../../routes/par.js';
import { buildRouteApp } from '../helpers/route-app.js';

describe('POST /as/par', () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it('returns request_uri from PARService', async () => {
    mocked.parseAndStore.mockResolvedValue('urn:ietf:params:oauth:request_uri:test');

    const app = await buildRouteApp(parRoute);
    const response = await app.inject({
      method: 'POST',
      url: '/as/par',
      payload: 'client_id=test&request=signed',
      headers: { 'content-type': 'text/plain' }
    });

    expect(response.statusCode).toBe(201);
    expect(response.json()).toEqual({
      expires_in: 60,
      request_uri: 'urn:ietf:params:oauth:request_uri:test'
    });

    await app.close();
  });
});
