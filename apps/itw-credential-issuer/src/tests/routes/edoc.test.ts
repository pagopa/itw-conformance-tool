import { EdocProofInitError } from '@itw-conformance-tool/issuer';
import { afterEach, describe, expect, it, vi } from 'vitest';

const mocked = vi.hoisted(() => ({
  processInit: vi.fn()
}));

vi.mock('@itw-conformance-tool/issuer', async () => {
  const actual = await vi.importActual<typeof import('@itw-conformance-tool/issuer')>('@itw-conformance-tool/issuer');
  return {
    ...actual,
    EdocProofService: class {
      processInit = mocked.processInit;
    }
  };
});

import edocRoute from '../../routes/edoc.js';
import { buildRouteApp } from '../helpers/route-app.js';

const VALID_HEADERS = {
  'content-type': 'application/json',
  'oauth-client-attestation': 'header.payload.signature',
  'oauth-client-attestation-pop': 'header.payload.pop-signature'
};

const VALID_BODY = {
  mrtd_auth_session: 'test-session-id',
  mrtd_pop_jwt_nonce: 'dGVzdC1ub25jZQ'
};

describe('POST /edoc-proof/init', () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  describe('happy path', () => {
    it('returns 202 with Content-Type application/jwt and JWT body', async () => {
      mocked.processInit.mockResolvedValue('signed.response.jwt');

      const app = await buildRouteApp(edocRoute);
      const response = await app.inject({
        method: 'POST',
        url: '/edoc-proof/init',
        payload: JSON.stringify(VALID_BODY),
        headers: VALID_HEADERS
      });

      expect(response.statusCode).toBe(202);
      expect(response.headers['content-type']).toContain('application/jwt');
      expect(response.body).toBe('signed.response.jwt');

      await app.close();
    });

    it('calls EdocProofService.processInit with the correct arguments', async () => {
      mocked.processInit.mockResolvedValue('signed.response.jwt');

      const app = await buildRouteApp(edocRoute);
      await app.inject({
        method: 'POST',
        url: '/edoc-proof/init',
        payload: JSON.stringify(VALID_BODY),
        headers: VALID_HEADERS
      });

      expect(mocked.processInit).toHaveBeenCalledOnce();
      expect(mocked.processInit).toHaveBeenCalledWith(
        expect.objectContaining({
          mrtdAuthSessionId: VALID_BODY.mrtd_auth_session,
          mrtdPopJwtNonce: VALID_BODY.mrtd_pop_jwt_nonce,
          clientAttestationJwt: VALID_HEADERS['oauth-client-attestation'],
          clientAttestationPopJwt: VALID_HEADERS['oauth-client-attestation-pop'],
          baseURL: 'http://localhost:3000'
        })
      );

      await app.close();
    });
  });

  describe('schema validation', () => {
    it('returns 400 when oauth-client-attestation header is missing', async () => {
      const app = await buildRouteApp(edocRoute);
      const response = await app.inject({
        method: 'POST',
        url: '/edoc-proof/init',
        payload: JSON.stringify(VALID_BODY),
        headers: {
          'content-type': 'application/json',
          'oauth-client-attestation-pop': VALID_HEADERS['oauth-client-attestation-pop']
        }
      });

      expect(response.statusCode).toBe(400);
      await app.close();
    });

    it('returns 400 when oauth-client-attestation-pop header is missing', async () => {
      const app = await buildRouteApp(edocRoute);
      const response = await app.inject({
        method: 'POST',
        url: '/edoc-proof/init',
        payload: JSON.stringify(VALID_BODY),
        headers: {
          'content-type': 'application/json',
          'oauth-client-attestation': VALID_HEADERS['oauth-client-attestation']
        }
      });

      expect(response.statusCode).toBe(400);
      await app.close();
    });

    it('returns 400 when mrtd_auth_session is missing from body', async () => {
      const app = await buildRouteApp(edocRoute);
      const response = await app.inject({
        method: 'POST',
        url: '/edoc-proof/init',
        payload: JSON.stringify({ mrtd_pop_jwt_nonce: VALID_BODY.mrtd_pop_jwt_nonce }),
        headers: VALID_HEADERS
      });

      expect(response.statusCode).toBe(400);
      await app.close();
    });

    it('returns 400 when mrtd_pop_jwt_nonce is missing from body', async () => {
      const app = await buildRouteApp(edocRoute);
      const response = await app.inject({
        method: 'POST',
        url: '/edoc-proof/init',
        payload: JSON.stringify({ mrtd_auth_session: VALID_BODY.mrtd_auth_session }),
        headers: VALID_HEADERS
      });

      expect(response.statusCode).toBe(400);
      await app.close();
    });
  });

  describe('error handling', () => {
    it('returns 400 with invalid_request when EdocProofInitError statusCode is 400', async () => {
      mocked.processInit.mockRejectedValue(new EdocProofInitError('nonce mismatch', 400));

      const app = await buildRouteApp(edocRoute);
      const response = await app.inject({
        method: 'POST',
        url: '/edoc-proof/init',
        payload: JSON.stringify(VALID_BODY),
        headers: VALID_HEADERS
      });

      expect(response.statusCode).toBe(400);
      expect(response.json()).toMatchObject({
        error: 'invalid_request',
        error_description: 'nonce mismatch'
      });

      await app.close();
    });

    it('returns 403 with access_denied when EdocProofInitError statusCode is 403', async () => {
      mocked.processInit.mockRejectedValue(new EdocProofInitError('nonce already used', 403));

      const app = await buildRouteApp(edocRoute);
      const response = await app.inject({
        method: 'POST',
        url: '/edoc-proof/init',
        payload: JSON.stringify(VALID_BODY),
        headers: VALID_HEADERS
      });

      expect(response.statusCode).toBe(403);
      expect(response.json()).toMatchObject({
        error: 'access_denied',
        error_description: 'nonce already used'
      });

      await app.close();
    });

    it('returns 401 with invalid_client when EdocProofInitError statusCode is 401', async () => {
      mocked.processInit.mockRejectedValue(
        new EdocProofInitError('OAuth-Client-Attestation-PoP verification failed', 401)
      );

      const app = await buildRouteApp(edocRoute);
      const response = await app.inject({
        method: 'POST',
        url: '/edoc-proof/init',
        payload: JSON.stringify(VALID_BODY),
        headers: VALID_HEADERS
      });

      expect(response.statusCode).toBe(401);
      expect(response.json()).toMatchObject({
        error: 'invalid_client',
        error_description: 'OAuth-Client-Attestation-PoP verification failed'
      });

      await app.close();
    });

    it('returns 503 with temporarily_unavailable for unexpected errors', async () => {
      mocked.processInit.mockRejectedValue(new Error('database crashed'));

      const app = await buildRouteApp(edocRoute);
      const response = await app.inject({
        method: 'POST',
        url: '/edoc-proof/init',
        payload: JSON.stringify(VALID_BODY),
        headers: VALID_HEADERS
      });

      expect(response.statusCode).toBe(503);
      expect(response.json()).toEqual({ error: 'temporarily_unavailable' });

      await app.close();
    });
  });
});
