import { afterEach, describe, expect, it, vi } from 'vitest';

const mocked = vi.hoisted(() => ({
  authorize: vi.fn()
}));

vi.mock('../../services/mock-idp-service.js', async () => {
  const actual = await vi.importActual<typeof import('../../services/mock-idp-service.js')>(
    '../../services/mock-idp-service.js'
  );

  return {
    ...actual,
    MockIdpService: class {
      authorize = mocked.authorize;
    }
  };
});

import mockIdpRoute from '../../routes/mock-idp.js';
import { MockIdpRequestError } from '../../services/mock-idp-service.js';
import { buildRouteApp } from '../helpers/route-app.js';

describe('GET /idp/authorize', () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it('returns redirect when mock idp auth succeeds', async () => {
    mocked.authorize.mockResolvedValue({
      location: 'https://wallet.example/cb?challenge_info=abc&state=state'
    });

    const app = await buildRouteApp(mockIdpRoute);
    const response = await app.inject({ method: 'GET', url: '/idp/authorize?request_uri=urn:test' });

    expect(response.statusCode).toBe(302);
    expect(response.headers.location).toBe('https://wallet.example/cb?challenge_info=abc&state=state');

    await app.close();
  });

  it('returns invalid_request for known business errors', async () => {
    mocked.authorize.mockRejectedValue(new MockIdpRequestError('request_uri not found', 400));

    const app = await buildRouteApp(mockIdpRoute);
    const response = await app.inject({ method: 'GET', url: '/idp/authorize?request_uri=urn:missing' });

    expect(response.statusCode).toBe(400);
    expect(response.json()).toEqual({
      error: 'invalid_request',
      error_description: 'request_uri not found'
    });

    await app.close();
  });
});
