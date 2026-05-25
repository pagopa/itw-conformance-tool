import { afterEach, describe, expect, it, vi } from 'vitest';

const mocked = vi.hoisted(() => ({
  generate: vi.fn()
}));

vi.mock('@itw-conformance-tool/issuer', async () => {
  const actual = await vi.importActual<typeof import('@itw-conformance-tool/issuer')>('@itw-conformance-tool/issuer');
  return {
    ...actual,
    NonceService: class {
      generate = mocked.generate;
    }
  };
});

import nonceRoute from '../../routes/nonce.js';
import { buildRouteApp } from '../helpers/route-app.js';

describe('POST /nonce', () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it('returns generated nonce', async () => {
    mocked.generate.mockResolvedValue('nonce-value');

    const app = await buildRouteApp(nonceRoute);
    const response = await app.inject({
      method: 'POST',
      url: '/nonce'
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ c_nonce: 'nonce-value' });

    await app.close();
  });
});
