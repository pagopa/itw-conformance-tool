import { afterEach, describe, expect, it, vi } from 'vitest';

const mocked = vi.hoisted(() => ({
  createCredential: vi.fn()
}));

vi.mock('@itw-conformance-tool/issuer', async () => {
  const actual = await vi.importActual<typeof import('@itw-conformance-tool/issuer')>('@itw-conformance-tool/issuer');
  return {
    ...actual,
    CredentialService: class {
      createCredential = mocked.createCredential;
    }
  };
});

import credentialRoute from '../../routes/credential.js';
import { buildRouteApp } from '../helpers/route-app.js';

describe('POST /credential', () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it('returns credential response from CredentialService', async () => {
    mocked.createCredential.mockResolvedValue({
      credentials: [{ credential: 'signed-credential' }]
    });

    const app = await buildRouteApp(credentialRoute);
    const response = await app.inject({
      method: 'POST',
      url: '/credential',
      payload: JSON.stringify({ proof: { proof_type: 'jwt', jwt: 'proof-jwt' } }),
      headers: { 'content-type': 'application/json' }
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      credentials: [{ credential: 'signed-credential' }]
    });

    await app.close();
  });
});
