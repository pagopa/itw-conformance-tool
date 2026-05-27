import { SignJWT, generateKeyPair, exportJWK } from 'jose';
import { describe, expect, it } from 'vitest';

import edocProofVerifyRoute from '../../routes/edoc-proof.js';
import { buildRouteApp } from '../helpers/route-app.js';

describe('POST /edoc-proof/verify', () => {
  it('returns 400 if headers are missing', async () => {
    const app = await buildRouteApp(edocProofVerifyRoute);

    const response = await app.inject({
      method: 'POST',
      url: '/edoc-proof/verify',
      payload: {}
    });

    expect(response.statusCode).toBe(400);
  });

  it('returns 400 if session is not found in repository', async () => {
    const app = await buildRouteApp(edocProofVerifyRoute);

    const { privateKey, publicKey } = await generateKeyPair('ES256');
    const jwk = await exportJWK(publicKey);

    const attestation = await new SignJWT({ cnf: { jwk } })
      .setProtectedHeader({ alg: 'ES256', typ: 'wallet-attestation+jwt' })
      .sign(privateKey);

    const pop = await new SignJWT({})
      .setProtectedHeader({ alg: 'ES256', typ: 'wallet-attestation-pop+jwt' })
      .sign(privateKey);

    const response = await app.inject({
      method: 'POST',
      url: '/edoc-proof/verify',
      headers: {
        'oauth-client-attestation': attestation,
        'oauth-client-attestation-pop': pop
      },
      payload: {
        mrtd_auth_session: 'unknown_session',
        mrtd_pop_nonce: 'some_nonce',
        mrtd_validation_jwt: 'some_jwt'
      }
    });

    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.error_description).toBe('Session not found or expired');
  });
});
