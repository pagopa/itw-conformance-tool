import { afterEach, describe, expect, it, vi } from 'vitest';

const mocked = vi.hoisted(() => ({
  handle: vi.fn()
}));

vi.mock('@itw-conformance-tool/issuer', async () => {
  const actual = await vi.importActual<typeof import('@itw-conformance-tool/issuer')>('@itw-conformance-tool/issuer');
  return {
    ...actual,
    PresentationResponseService: class {
      handle = mocked.handle;
    }
  };
});

import presentationResponseRoute from '../../routes/presentation-response.js';
import { buildRouteApp } from '../helpers/route-app.js';

describe('POST /presentation-response', () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it('returns redirect_uri from PresentationResponseService', async () => {
    mocked.handle.mockResolvedValue({
      redirectUri: 'http://localhost:3000/code/jwt?request_uri=urn:test'
    });

    const app = await buildRouteApp(presentationResponseRoute);
    const response = await app.inject({
      method: 'POST',
      url: '/presentation-response?request_uri=urn:test',
      payload: 'response=jwt',
      headers: { 'content-type': 'text/plain' }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      redirect_uri: 'http://localhost:3000/code/jwt?request_uri=urn:test'
    });

    await app.close();
  });
});
