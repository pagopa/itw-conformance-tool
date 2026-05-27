import { type JWK, SignJWT, exportJWK, generateKeyPair, importJWK, jwtVerify } from 'jose';
import { beforeAll, describe, expect, it, vi } from 'vitest';

import { EdocProofService } from '../services/edoc-proof-service.js';

import type { IEdocParRepository } from '../services/edoc-proof-service.js';
import type { JwksRepository } from '../signer.js';
import type { MrtdAuthSession, ParRequest } from '../z-par.js';

interface EcKeyMaterial {
  privateJwk: JWK & { kty: 'EC'; kid: string; alg: string; d: string };
  publicJwk: JWK & { kty: 'EC'; kid: string; alg: string };
}

async function generateEcKeyMaterial(kid: string): Promise<EcKeyMaterial> {
  const { privateKey, publicKey } = await generateKeyPair('ES256');
  const prv = await exportJWK(privateKey);
  const pub = await exportJWK(publicKey);
  return {
    privateJwk: { ...prv, kty: 'EC' as const, kid, alg: 'ES256', d: prv.d as string },
    publicJwk: { ...pub, kty: 'EC' as const, kid, alg: 'ES256' }
  };
}

function buildJwksRepository(keys: EcKeyMaterial): JwksRepository {
  return {
    getSign: () =>
      ({ private: keys.privateJwk, public: keys.publicJwk }) as unknown as ReturnType<JwksRepository['getSign']>,
    getEncrypt: () =>
      ({ private: keys.privateJwk, public: keys.publicJwk }) as unknown as ReturnType<JwksRepository['getEncrypt']>,
    iacaX509: () => 'CERT'
  };
}

async function buildClientAttestationJwts(
  audience: string
): Promise<{ attestationJwt: string; attestationPopJwt: string }> {
  const { privateKey, publicKey } = await generateKeyPair('ES256');
  const walletPublicJwk = { ...(await exportJWK(publicKey)), alg: 'ES256', kid: 'wallet-key' };

  // The attestation JWT embeds its signing key in the 'jwk' protected header parameter so
  // the verifier can check the signature without a pre-registered trust anchor.
  const attestationJwt = await new SignJWT({ cnf: { jwk: walletPublicJwk } })
    .setProtectedHeader({ alg: 'ES256', jwk: walletPublicJwk })
    .setIssuer('https://wallet-provider.example.it')
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(privateKey);

  // The PoP must be signed by the wallet key (cnf.jwk private counterpart) and include aud.
  const attestationPopJwt = await new SignJWT({ iss: 'wallet-client-id' })
    .setProtectedHeader({ alg: 'ES256', typ: 'oauth-client-attestation-pop+jwt' })
    .setAudience(audience)
    .setIssuedAt()
    .setExpirationTime('1h')
    .sign(privateKey);

  return { attestationJwt, attestationPopJwt };
}

function makeMockRepo(overrides: Partial<IEdocParRepository> = {}): IEdocParRepository {
  return {
    getByMrtdAuthSession: vi.fn().mockResolvedValue(undefined),
    atomicClaimSession: vi.fn().mockResolvedValue(true),
    ...overrides
  };
}

const BASE_URL = 'http://localhost:3000';
const SESSION_ID = 'test-mrtd-session-abc';
const NONCE = 'dGVzdC1ub25jZXZhbHVl'; // base64url: "test-noncevalue"

function makeValidSession(overrides: Partial<MrtdAuthSession> = {}): MrtdAuthSession {
  return {
    auth_flow: 'l2plus',
    created_at: Date.now() - 1000,
    expires_at: Date.now() + 60_000,
    identity: {
      birthdate: '1990-01-01',
      family_name: 'Rossi',
      given_name: 'Mario',
      personal_administrative_number: 'RSSMRA90A01H501Z',
      place_of_birth: { country: 'IT', locality: 'Rome', region: 'RM' }
    },
    mrtd_auth_session: SESSION_ID,
    mrtd_pop_jwt_nonce: NONCE,
    status: 'pending_mrtd_init',
    ...overrides
  };
}

function makeParRequest(session: MrtdAuthSession): ParRequest {
  return {
    authorization_details: [{ credential_configuration_id: 'MDL', type: 'openid_credential' }],
    client_id: 'test-client-id',
    code_challenge: 'dGVzdC1jaGFsbGVuZ2U',
    code_challenge_method: 'S256',
    id: 'par-id',
    mrtd_auth_session: session,
    redirect_uri: 'https://wallet.example.com/cb',
    request_uri: 'urn:ietf:params:oauth:request_uri:test',
    response_type: 'code',
    state: 'state123'
  } as unknown as ParRequest;
}

describe('EdocProofService.processInit', () => {
  let issuerKeys: EcKeyMaterial;

  beforeAll(async () => {
    issuerKeys = await generateEcKeyMaterial('issuer-sign-key');
  });

  describe('happy path', () => {
    it('returns a JWT with the correct claims and header', async () => {
      const { attestationJwt, attestationPopJwt } = await buildClientAttestationJwts(BASE_URL);
      const session = makeValidSession();
      const parRequest = makeParRequest(session);
      const repo = makeMockRepo({
        getByMrtdAuthSession: vi
          .fn()
          .mockResolvedValue({ parRequest, requestUri: 'urn:ietf:params:oauth:request_uri:test' })
      });

      const service = new EdocProofService(repo, buildJwksRepository(issuerKeys));
      const jwt = await service.processInit({
        baseURL: BASE_URL,
        clientAttestationJwt: attestationJwt,
        clientAttestationPopJwt: attestationPopJwt,
        mrtdAuthSessionId: SESSION_ID,
        mrtdPopJwtNonce: NONCE
      });

      const issuerPublicKey = await importJWK(issuerKeys.publicJwk, 'ES256');
      const { payload, protectedHeader } = await jwtVerify(jwt, issuerPublicKey);

      expect(protectedHeader.typ).toBe('mrtd-ias-pop+jwt');
      expect(protectedHeader.alg).toBe('ES256');
      expect(protectedHeader.kid).toBe('issuer-sign-key');

      expect(payload.iss).toBe(BASE_URL);
      expect(payload.aud).toBe('test-client-id');
      expect(payload.htm).toBe('POST');
      expect(payload.htu).toBe(`${BASE_URL}/edoc-proof/verify`);
      expect(payload.iat).toBeDefined();
      expect(payload.exp).toBeGreaterThan(payload.iat as number);
    });

    it('generates a 256-bit challenge (32 bytes → 43 base64url chars)', async () => {
      const { attestationJwt, attestationPopJwt } = await buildClientAttestationJwts(BASE_URL);
      const parRequest = makeParRequest(makeValidSession());
      const repo = makeMockRepo({
        getByMrtdAuthSession: vi.fn().mockResolvedValue({ parRequest, requestUri: 'urn:test' })
      });

      const service = new EdocProofService(repo, buildJwksRepository(issuerKeys));
      const jwt = await service.processInit({
        baseURL: BASE_URL,
        clientAttestationJwt: attestationJwt,
        clientAttestationPopJwt: attestationPopJwt,
        mrtdAuthSessionId: SESSION_ID,
        mrtdPopJwtNonce: NONCE
      });

      const issuerPublicKey = await importJWK(issuerKeys.publicJwk, 'ES256');
      const { payload } = await jwtVerify(jwt, issuerPublicKey);

      expect(typeof payload.challenge).toBe('string');
      expect((payload.challenge as string).length).toBe(43); // 32 bytes = 256 bits in base64url
    });

    it('generates a 128-bit mrtd_pop_nonce (16 bytes → 22 base64url chars)', async () => {
      const { attestationJwt, attestationPopJwt } = await buildClientAttestationJwts(BASE_URL);
      const parRequest = makeParRequest(makeValidSession());
      const repo = makeMockRepo({
        getByMrtdAuthSession: vi.fn().mockResolvedValue({ parRequest, requestUri: 'urn:test' })
      });

      const service = new EdocProofService(repo, buildJwksRepository(issuerKeys));
      const jwt = await service.processInit({
        baseURL: BASE_URL,
        clientAttestationJwt: attestationJwt,
        clientAttestationPopJwt: attestationPopJwt,
        mrtdAuthSessionId: SESSION_ID,
        mrtdPopJwtNonce: NONCE
      });

      const issuerPublicKey = await importJWK(issuerKeys.publicJwk, 'ES256');
      const { payload } = await jwtVerify(jwt, issuerPublicKey);

      expect(typeof payload.mrtd_pop_nonce).toBe('string');
      expect((payload.mrtd_pop_nonce as string).length).toBe(22); // 16 bytes = 128 bits in base64url
    });

    it('transitions the session to pending_mrtd_verify and marks nonce as consumed', async () => {
      const { attestationJwt, attestationPopJwt } = await buildClientAttestationJwts(BASE_URL);
      const session = makeValidSession();
      const parRequest = makeParRequest(session);
      const atomicClaimSession = vi.fn().mockResolvedValue(true);
      const repo = makeMockRepo({
        getByMrtdAuthSession: vi.fn().mockResolvedValue({ parRequest, requestUri: 'urn:test' }),
        atomicClaimSession
      });

      const service = new EdocProofService(repo, buildJwksRepository(issuerKeys));
      await service.processInit({
        baseURL: BASE_URL,
        clientAttestationJwt: attestationJwt,
        clientAttestationPopJwt: attestationPopJwt,
        mrtdAuthSessionId: SESSION_ID,
        mrtdPopJwtNonce: NONCE
      });

      expect(atomicClaimSession).toHaveBeenCalledOnce();
      const [calledUri, calledSessionId, updatedPar] = atomicClaimSession.mock.calls[0] as [
        string,
        string,
        ParRequest & { mrtd_auth_session: MrtdAuthSession }
      ];
      expect(calledUri).toBe('urn:test');
      expect(calledSessionId).toBe(SESSION_ID);
      expect(updatedPar.mrtd_auth_session.status).toBe('pending_mrtd_verify');
      expect(updatedPar.mrtd_auth_session.mrtd_pop_jwt_nonce_consumed_at).toBeGreaterThan(0);
      expect(typeof updatedPar.mrtd_auth_session.challenge).toBe('string');
      expect(typeof updatedPar.mrtd_auth_session.mrtd_pop_nonce).toBe('string');
      // wallet_public_key must be persisted so subsequent steps (/edoc-proof/verify, /idp/callback)
      // can verify wallet-bound proofs without requiring attestation headers again.
      expect(updatedPar.mrtd_auth_session.wallet_public_key).toBeDefined();
      expect(typeof updatedPar.mrtd_auth_session.wallet_public_key).toBe('object');
      expect((updatedPar.mrtd_auth_session.wallet_public_key as Record<string, unknown>)['kty']).toBe('EC');
      expect((updatedPar.mrtd_auth_session.wallet_public_key as Record<string, unknown>)['d']).toBeUndefined();
    });

    it('produces different challenges on each call (randomness check)', async () => {
      const parRequest = makeParRequest(makeValidSession());
      const makeRepo = () =>
        makeMockRepo({
          getByMrtdAuthSession: vi.fn().mockResolvedValue({ parRequest, requestUri: 'urn:test' })
        });
      const issuerPublicKey = await importJWK(issuerKeys.publicJwk, 'ES256');

      const [ats1, ats2] = await Promise.all([
        buildClientAttestationJwts(BASE_URL),
        buildClientAttestationJwts(BASE_URL)
      ]);

      const jwt1 = await new EdocProofService(makeRepo(), buildJwksRepository(issuerKeys)).processInit({
        baseURL: BASE_URL,
        clientAttestationJwt: ats1.attestationJwt,
        clientAttestationPopJwt: ats1.attestationPopJwt,
        mrtdAuthSessionId: SESSION_ID,
        mrtdPopJwtNonce: NONCE
      });

      const jwt2 = await new EdocProofService(makeRepo(), buildJwksRepository(issuerKeys)).processInit({
        baseURL: BASE_URL,
        clientAttestationJwt: ats2.attestationJwt,
        clientAttestationPopJwt: ats2.attestationPopJwt,
        mrtdAuthSessionId: SESSION_ID,
        mrtdPopJwtNonce: NONCE
      });

      const { payload: p1 } = await jwtVerify(jwt1, issuerPublicKey);
      const { payload: p2 } = await jwtVerify(jwt2, issuerPublicKey);

      expect(p1.challenge).not.toBe(p2.challenge);
      expect(p1.mrtd_pop_nonce).not.toBe(p2.mrtd_pop_nonce);
    });
  });

  describe('OAuth-Client-Attestation validation', () => {
    it('throws EdocProofInitError (401) when the attestation JWT is not a valid JWT', async () => {
      const { attestationPopJwt } = await buildClientAttestationJwts(BASE_URL);
      const service = new EdocProofService(makeMockRepo(), buildJwksRepository(issuerKeys));

      await expect(
        service.processInit({
          baseURL: BASE_URL,
          clientAttestationJwt: 'not-a-valid-jwt',
          clientAttestationPopJwt: attestationPopJwt,
          mrtdAuthSessionId: SESSION_ID,
          mrtdPopJwtNonce: NONCE
        })
      ).rejects.toMatchObject({ statusCode: 401 });
    });

    it('throws EdocProofInitError (401) when the attestation JWT is missing cnf.jwk', async () => {
      const { privateKey, publicKey } = await generateKeyPair('ES256');
      const pubJwk = { ...(await exportJWK(publicKey)), alg: 'ES256', kid: 'wallet-key' };
      const attestationJwt = await new SignJWT({ no_cnf: true })
        .setProtectedHeader({ alg: 'ES256', jwk: pubJwk })
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(privateKey);
      const { attestationPopJwt } = await buildClientAttestationJwts(BASE_URL);

      const service = new EdocProofService(makeMockRepo(), buildJwksRepository(issuerKeys));

      await expect(
        service.processInit({
          baseURL: BASE_URL,
          clientAttestationJwt: attestationJwt,
          clientAttestationPopJwt: attestationPopJwt,
          mrtdAuthSessionId: SESSION_ID,
          mrtdPopJwtNonce: NONCE
        })
      ).rejects.toMatchObject({ statusCode: 401 });
    });

    it('throws EdocProofInitError (401) when the PoP is signed with a different key than cnf.jwk', async () => {
      const { privateKey: walletPrivate, publicKey: walletPublic } = await generateKeyPair('ES256');
      const { privateKey: wrongPrivate } = await generateKeyPair('ES256');
      const walletPublicJwk = { ...(await exportJWK(walletPublic)), alg: 'ES256', kid: 'wallet-key' };

      const attestationJwt = await new SignJWT({ cnf: { jwk: walletPublicJwk } })
        .setProtectedHeader({ alg: 'ES256', jwk: walletPublicJwk })
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(walletPrivate);

      const attestationPopJwt = await new SignJWT({ iss: 'wallet-client-id' })
        .setProtectedHeader({ alg: 'ES256', typ: 'oauth-client-attestation-pop+jwt' })
        .setAudience(BASE_URL)
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(wrongPrivate); // wrong key — signature mismatch

      const service = new EdocProofService(makeMockRepo(), buildJwksRepository(issuerKeys));

      await expect(
        service.processInit({
          baseURL: BASE_URL,
          clientAttestationJwt: attestationJwt,
          clientAttestationPopJwt: attestationPopJwt,
          mrtdAuthSessionId: SESSION_ID,
          mrtdPopJwtNonce: NONCE
        })
      ).rejects.toMatchObject({ statusCode: 401 });
    });

    it('throws EdocProofInitError (401) when the PoP audience does not match baseURL', async () => {
      const { privateKey, publicKey } = await generateKeyPair('ES256');
      const walletPublicJwk = { ...(await exportJWK(publicKey)), alg: 'ES256', kid: 'wallet-key' };

      const attestationJwt = await new SignJWT({ cnf: { jwk: walletPublicJwk } })
        .setProtectedHeader({ alg: 'ES256', jwk: walletPublicJwk })
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(privateKey);

      // PoP targets the wrong audience
      const attestationPopJwt = await new SignJWT({ iss: 'wallet-client-id' })
        .setProtectedHeader({ alg: 'ES256', typ: 'oauth-client-attestation-pop+jwt' })
        .setAudience('https://wrong-audience.example.it')
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(privateKey);

      const service = new EdocProofService(makeMockRepo(), buildJwksRepository(issuerKeys));

      await expect(
        service.processInit({
          baseURL: BASE_URL,
          clientAttestationJwt: attestationJwt,
          clientAttestationPopJwt: attestationPopJwt,
          mrtdAuthSessionId: SESSION_ID,
          mrtdPopJwtNonce: NONCE
        })
      ).rejects.toMatchObject({ statusCode: 401 });
    });

    it('throws EdocProofInitError (401) when cnf.jwk contains private key material', async () => {
      const { privateKey, publicKey } = await generateKeyPair('ES256');
      const pubJwk = { ...(await exportJWK(publicKey)), alg: 'ES256', kid: 'wallet-key' };
      // Deliberately embed the private key in cnf.jwk
      const privJwk = { ...(await exportJWK(privateKey)), alg: 'ES256', kid: 'wallet-key' };

      const attestationJwt = await new SignJWT({ cnf: { jwk: privJwk } })
        .setProtectedHeader({ alg: 'ES256', jwk: pubJwk })
        .setIssuedAt()
        .setExpirationTime('1h')
        .sign(privateKey);

      const { attestationPopJwt } = await buildClientAttestationJwts(BASE_URL);
      const service = new EdocProofService(makeMockRepo(), buildJwksRepository(issuerKeys));

      await expect(
        service.processInit({
          baseURL: BASE_URL,
          clientAttestationJwt: attestationJwt,
          clientAttestationPopJwt: attestationPopJwt,
          mrtdAuthSessionId: SESSION_ID,
          mrtdPopJwtNonce: NONCE
        })
      ).rejects.toMatchObject({ statusCode: 401, message: expect.stringContaining('private key') });
    });
  });

  describe('session validation', () => {
    it('throws EdocProofInitError (400) when mrtd_auth_session is not found in PAR', async () => {
      const { attestationJwt, attestationPopJwt } = await buildClientAttestationJwts(BASE_URL);
      const service = new EdocProofService(makeMockRepo(), buildJwksRepository(issuerKeys));

      await expect(
        service.processInit({
          baseURL: BASE_URL,
          clientAttestationJwt: attestationJwt,
          clientAttestationPopJwt: attestationPopJwt,
          mrtdAuthSessionId: 'unknown-session-id',
          mrtdPopJwtNonce: NONCE
        })
      ).rejects.toMatchObject({ statusCode: 400, message: expect.stringContaining('not found') });
    });

    it('throws EdocProofInitError (400) when the PAR entry has no mrtd_auth_session field', async () => {
      const { attestationJwt, attestationPopJwt } = await buildClientAttestationJwts(BASE_URL);
      const parRequest = {
        ...makeParRequest(makeValidSession()),
        mrtd_auth_session: undefined
      } as unknown as ParRequest;
      const repo = makeMockRepo({
        getByMrtdAuthSession: vi.fn().mockResolvedValue({ parRequest, requestUri: 'urn:test' })
      });

      const service = new EdocProofService(repo, buildJwksRepository(issuerKeys));

      await expect(
        service.processInit({
          baseURL: BASE_URL,
          clientAttestationJwt: attestationJwt,
          clientAttestationPopJwt: attestationPopJwt,
          mrtdAuthSessionId: SESSION_ID,
          mrtdPopJwtNonce: NONCE
        })
      ).rejects.toMatchObject({ statusCode: 400 });
    });

    it('throws EdocProofInitError (400) when the session is expired', async () => {
      const { attestationJwt, attestationPopJwt } = await buildClientAttestationJwts(BASE_URL);
      const parRequest = makeParRequest(makeValidSession({ expires_at: Date.now() - 1000 }));
      const repo = makeMockRepo({
        getByMrtdAuthSession: vi.fn().mockResolvedValue({ parRequest, requestUri: 'urn:test' })
      });

      const service = new EdocProofService(repo, buildJwksRepository(issuerKeys));

      await expect(
        service.processInit({
          baseURL: BASE_URL,
          clientAttestationJwt: attestationJwt,
          clientAttestationPopJwt: attestationPopJwt,
          mrtdAuthSessionId: SESSION_ID,
          mrtdPopJwtNonce: NONCE
        })
      ).rejects.toMatchObject({ statusCode: 400, message: expect.stringContaining('expired') });
    });

    it('throws EdocProofInitError (403) when status is pending_mrtd_verify', async () => {
      const { attestationJwt, attestationPopJwt } = await buildClientAttestationJwts(BASE_URL);
      const parRequest = makeParRequest(makeValidSession({ status: 'pending_mrtd_verify' }));
      const repo = makeMockRepo({
        getByMrtdAuthSession: vi.fn().mockResolvedValue({ parRequest, requestUri: 'urn:test' })
      });

      const service = new EdocProofService(repo, buildJwksRepository(issuerKeys));

      await expect(
        service.processInit({
          baseURL: BASE_URL,
          clientAttestationJwt: attestationJwt,
          clientAttestationPopJwt: attestationPopJwt,
          mrtdAuthSessionId: SESSION_ID,
          mrtdPopJwtNonce: NONCE
        })
      ).rejects.toMatchObject({ statusCode: 403 });
    });

    it('throws EdocProofInitError (403) when status is verified', async () => {
      const { attestationJwt, attestationPopJwt } = await buildClientAttestationJwts(BASE_URL);
      const parRequest = makeParRequest(makeValidSession({ status: 'verified' }));
      const repo = makeMockRepo({
        getByMrtdAuthSession: vi.fn().mockResolvedValue({ parRequest, requestUri: 'urn:test' })
      });

      const service = new EdocProofService(repo, buildJwksRepository(issuerKeys));

      await expect(
        service.processInit({
          baseURL: BASE_URL,
          clientAttestationJwt: attestationJwt,
          clientAttestationPopJwt: attestationPopJwt,
          mrtdAuthSessionId: SESSION_ID,
          mrtdPopJwtNonce: NONCE
        })
      ).rejects.toMatchObject({ statusCode: 403 });
    });

    it('throws EdocProofInitError (400) when status is created (wrong state, not anti-replay)', async () => {
      const { attestationJwt, attestationPopJwt } = await buildClientAttestationJwts(BASE_URL);
      const parRequest = makeParRequest(makeValidSession({ status: 'created' }));
      const repo = makeMockRepo({
        getByMrtdAuthSession: vi.fn().mockResolvedValue({ parRequest, requestUri: 'urn:test' })
      });

      const service = new EdocProofService(repo, buildJwksRepository(issuerKeys));

      await expect(
        service.processInit({
          baseURL: BASE_URL,
          clientAttestationJwt: attestationJwt,
          clientAttestationPopJwt: attestationPopJwt,
          mrtdAuthSessionId: SESSION_ID,
          mrtdPopJwtNonce: NONCE
        })
      ).rejects.toMatchObject({ statusCode: 400 });
    });
  });

  describe('nonce validation', () => {
    it('throws EdocProofInitError (400) when mrtd_pop_jwt_nonce does not match', async () => {
      const { attestationJwt, attestationPopJwt } = await buildClientAttestationJwts(BASE_URL);
      const parRequest = makeParRequest(makeValidSession());
      const repo = makeMockRepo({
        getByMrtdAuthSession: vi.fn().mockResolvedValue({ parRequest, requestUri: 'urn:test' })
      });

      const service = new EdocProofService(repo, buildJwksRepository(issuerKeys));

      await expect(
        service.processInit({
          baseURL: BASE_URL,
          clientAttestationJwt: attestationJwt,
          clientAttestationPopJwt: attestationPopJwt,
          mrtdAuthSessionId: SESSION_ID,
          mrtdPopJwtNonce: 'wrong-nonce-entirely'
        })
      ).rejects.toMatchObject({ statusCode: 400, message: expect.stringContaining('nonce') });
    });

    it('throws EdocProofInitError (403) when mrtd_pop_jwt_nonce was already consumed (anti-replay)', async () => {
      const { attestationJwt, attestationPopJwt } = await buildClientAttestationJwts(BASE_URL);
      const parRequest = makeParRequest(makeValidSession({ mrtd_pop_jwt_nonce_consumed_at: Date.now() - 5000 }));
      const repo = makeMockRepo({
        getByMrtdAuthSession: vi.fn().mockResolvedValue({ parRequest, requestUri: 'urn:test' })
      });

      const service = new EdocProofService(repo, buildJwksRepository(issuerKeys));

      await expect(
        service.processInit({
          baseURL: BASE_URL,
          clientAttestationJwt: attestationJwt,
          clientAttestationPopJwt: attestationPopJwt,
          mrtdAuthSessionId: SESSION_ID,
          mrtdPopJwtNonce: NONCE
        })
      ).rejects.toMatchObject({ statusCode: 403, message: expect.stringContaining('already been used') });
    });

    it('throws EdocProofInitError (403) when atomicClaimSession loses a concurrent race', async () => {
      const { attestationJwt, attestationPopJwt } = await buildClientAttestationJwts(BASE_URL);
      const parRequest = makeParRequest(makeValidSession());
      const repo = makeMockRepo({
        getByMrtdAuthSession: vi.fn().mockResolvedValue({ parRequest, requestUri: 'urn:test' }),
        // Simulate another request having already claimed the session
        atomicClaimSession: vi.fn().mockResolvedValue(false)
      });

      const service = new EdocProofService(repo, buildJwksRepository(issuerKeys));

      await expect(
        service.processInit({
          baseURL: BASE_URL,
          clientAttestationJwt: attestationJwt,
          clientAttestationPopJwt: attestationPopJwt,
          mrtdAuthSessionId: SESSION_ID,
          mrtdPopJwtNonce: NONCE
        })
      ).rejects.toMatchObject({ statusCode: 403, message: expect.stringContaining('already been used') });
    });
  });
});
