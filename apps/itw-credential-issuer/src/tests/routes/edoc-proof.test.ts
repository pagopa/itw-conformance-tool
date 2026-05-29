import { SignJWT, generateKeyPair, exportJWK } from 'jose';
import { describe, expect, it, afterEach, vi } from 'vitest';

import edocProofVerifyRoute from '../../routes/edoc-proof.js';
import { buildRouteApp } from '../helpers/route-app.js';

import type { FastifyInstance } from 'fastify';

vi.mock('../../plugins/index.js', async () => {
  const actual = await vi.importActual<typeof import('../../plugins/index.js')>('../../plugins/index.js');
  return {
    ...actual,
    makeOauthCallbacks: vi.fn().mockReturnValue({ baseURL: 'http://localhost:3000' })
  };
});

describe('POST /edoc-proof/verify', () => {
  let app: FastifyInstance | undefined;

  afterEach(async () => {
    if (app) {
      await app.close();
    }
  });

  it('returns 400 if headers are missing', async () => {
    app = await buildRouteApp(edocProofVerifyRoute);

    const response = await app.inject({
      method: 'POST',
      url: '/edoc-proof/verify',
      payload: {}
    });

    expect(response.statusCode).toBe(400);
  });

  it('returns 400 if session is not found in repository', async () => {
    app = await buildRouteApp(edocProofVerifyRoute);

    const { privateKey, publicKey } = await generateKeyPair('ES256');
    const jwk = await exportJWK(publicKey);

    const attestation = await new SignJWT({ cnf: { jwk } })
      .setProtectedHeader({ alg: 'ES256', typ: 'wallet-attestation+jwt' })
      .sign(privateKey);

    const pop = await new SignJWT({})
      .setProtectedHeader({ alg: 'ES256', typ: 'wallet-attestation-pop+jwt' })
      .sign(privateKey);

    (app as any).parRepository.getByMrtdAuthSession = vi.fn().mockResolvedValue(undefined);
    (app as any).parRepository.update = vi.fn().mockResolvedValue(undefined);

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

  it('returns 400 if nonce is already consumed (Anti-Replay)', async () => {
    app = await buildRouteApp(edocProofVerifyRoute);

    const { privateKey, publicKey } = await generateKeyPair('ES256');
    const jwk = await exportJWK(publicKey);

    const attestation = await new SignJWT({ cnf: { jwk } })
      .setProtectedHeader({ alg: 'ES256', typ: 'wallet-attestation+jwt' })
      .sign(privateKey);

    const pop = await new SignJWT({})
      .setProtectedHeader({ alg: 'ES256', typ: 'wallet-attestation-pop+jwt' })
      .sign(privateKey);

    (app as any).parRepository.getByMrtdAuthSession = vi.fn().mockResolvedValue({
      requestUri: 'urn:test:uri',
      clientId: 'client-1',
      expiresAt: Date.now() + 60000,
      requestObject: JSON.stringify({
        mrtd_auth_session: {
          mrtd_auth_session: 'valid_session',
          status: 'pending_mrtd_verify',
          mrtd_pop_nonce: 'correct_nonce',
          mrtd_pop_nonce_consumed_at: 1234567890,
          expires_at: Math.floor(Date.now() / 1000) + 3600
        }
      })
    });
    (app as any).parRepository.update = vi.fn().mockResolvedValue(undefined);

    const response = await app.inject({
      method: 'POST',
      url: '/edoc-proof/verify',
      headers: {
        'oauth-client-attestation': attestation,
        'oauth-client-attestation-pop': pop
      },
      payload: {
        mrtd_auth_session: 'valid_session',
        mrtd_pop_nonce: 'correct_nonce',
        mrtd_validation_jwt: 'some_jwt'
      }
    });

    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.error_description).toBe('Nonce already consumed');
  });

  it('successfully processes a valid verification request (Happy Path)', async () => {
    app = await buildRouteApp(edocProofVerifyRoute);

    const { privateKey, publicKey } = await generateKeyPair('ES256');
    const jwk = await exportJWK(publicKey);

    const attestation = await new SignJWT({ cnf: { jwk } })
      .setProtectedHeader({ alg: 'ES256', typ: 'wallet-attestation+jwt' })
      .sign(privateKey);

    const pop = await new SignJWT({})
      .setProtectedHeader({ alg: 'ES256', typ: 'wallet-attestation-pop+jwt' })
      .sign(privateKey);

    const validationJwt = await new SignJWT({
      iss: 'some-wallet-iss',
      aud: 'http://localhost:3000',
      document_type: 'cie',
      mrtd: { dg1: 'YmFzZTY0', dg11: 'YmFzZTY0', sod_mrtd: 'YmFzZTY0' },
      ias: { ias_pk: 'YmFzZTY0', sod_ias: 'YmFzZTY0', challenge_signed: 'YmFzZTY0' }
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'mrtd-ias+jwt', kid: 'key-1' })
      .setIssuedAt()
      .setExpirationTime('10m')
      .sign(privateKey);

    (app as any).parRepository.getByMrtdAuthSession = vi.fn().mockResolvedValue({
      requestUri: 'urn:test:uri',
      clientId: 'client-1',
      expiresAt: Date.now() + 60000,
      requestObject: JSON.stringify({
        mrtd_auth_session: {
          mrtd_auth_session: 'valid_session',
          status: 'pending_mrtd_verify',
          mrtd_pop_nonce: 'correct_nonce',
          expires_at: Math.floor(Date.now() / 1000) + 3600
        }
      })
    });
    (app as any).parRepository.update = vi.fn().mockResolvedValue(undefined);

    const response = await app.inject({
      method: 'POST',
      url: '/edoc-proof/verify',
      headers: {
        'oauth-client-attestation': attestation,
        'oauth-client-attestation-pop': pop
      },
      payload: {
        mrtd_auth_session: 'valid_session',
        mrtd_pop_nonce: 'correct_nonce',
        mrtd_validation_jwt: validationJwt
      }
    });

    expect(response.statusCode).toBe(202);
    const body = JSON.parse(response.body);
    expect(body.status).toBe('require_interaction');
    expect(body.type).toBe('redirect_to_web');
    expect(body.mrtd_val_pop_nonce).toBeDefined();
  });
});
