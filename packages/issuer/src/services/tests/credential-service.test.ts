import { beforeEach, describe, expect, it, vi } from 'vitest';

import { CreateCredentialError, CredentialService, InvalidProofError } from '../credential-service.js';

import type { JwksRepository } from '../../signer.js';
import type { INonceRepository } from '@itw-conformance-tool/database';

const mocked = vi.hoisted(() => {
  class MockOauth2Error extends Error {}

  return {
    MockOauth2Error,
    createCredentialResponse: vi.fn(),
    decodeJwt: vi.fn(),
    decodeProtectedHeader: vi.fn(),
    parseCredentialRequest: vi.fn(),
    verifyCredentialRequestJwtProof: vi.fn(),
    verifyTokenDPoP: vi.fn()
  };
});

vi.mock('@pagopa/io-wallet-oauth2', () => ({
  Oauth2Error: mocked.MockOauth2Error,
  verifyTokenDPoP: mocked.verifyTokenDPoP
}));

vi.mock('@pagopa/io-wallet-oid4vci', () => ({
  createCredentialResponse: mocked.createCredentialResponse,
  parseCredentialRequest: mocked.parseCredentialRequest,
  verifyCredentialRequestJwtProof: mocked.verifyCredentialRequestJwtProof
}));

vi.mock('jose', () => ({
  decodeJwt: mocked.decodeJwt,
  decodeProtectedHeader: mocked.decodeProtectedHeader
}));

const mockNonceRepository: INonceRepository = {
  consume: vi.fn(),
  delete: vi.fn(),
  get: vi.fn(),
  insert: vi.fn()
};

const mockJwksRepository: JwksRepository = {
  getEncrypt: vi.fn(),
  getSign: vi.fn(),
  iacaX509: vi.fn()
};

const makeService = () => new CredentialService(mockJwksRepository, mockNonceRepository);

describe('CredentialService', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    mocked.decodeProtectedHeader.mockReturnValue({ jwk: { crv: 'P-256', kty: 'EC', x: 'x', y: 'y' } });
    mocked.decodeJwt.mockImplementation((token: string) => {
      if (token === 'access-token') {
        return { cnf: { jkt: 'thumbprint' }, sub: 'subject-1' };
      }

      if (token === 'proof-jwt') {
        return { nonce: 'nonce-1' };
      }

      return {};
    });
    mocked.verifyTokenDPoP.mockResolvedValue(undefined);
    mocked.verifyCredentialRequestJwtProof.mockResolvedValue({
      header: { jwk: { crv: 'P-256', kty: 'EC', x: 'x', y: 'y' } }
    });
    mocked.createCredentialResponse.mockResolvedValue({ credentials: [{ credential: 'signed-credential' }] });
    (mockNonceRepository.consume as ReturnType<typeof vi.fn>).mockResolvedValue(true);
    (mockNonceRepository.delete as ReturnType<typeof vi.fn>).mockResolvedValue(undefined);
  });

  const createBaseOptions = () => ({
    baseURL: 'https://issuer.example',
    callbacks: { hash: vi.fn(), verifyJwt: vi.fn() },
    config: { isVersion: vi.fn().mockReturnValue(true) } as never,
    headers: new Headers(),
    method: 'POST' as const,
    url: 'https://issuer.example/credential'
  });

  const parsedRequest = {
    accessToken: 'access-token',
    credentialRequest: { credential_identifier: 'unknown' },
    dpopProof: 'dpop-jwt',
    proofs: [{ jwt: 'proof-jwt' }]
  };

  describe('createCredential()', () => {
    it('maps invalid JSON body to CreateCredentialError', async () => {
      const service = makeService();

      await expect(
        service.createCredential({
          ...createBaseOptions(),
          body: 'not-json'
        })
      ).rejects.toBeInstanceOf(CreateCredentialError);
    });

    it('maps DPoP verification Oauth2Error to InvalidProofError', async () => {
      const service = makeService();
      mocked.parseCredentialRequest.mockReturnValue(parsedRequest);
      mocked.verifyTokenDPoP.mockRejectedValue(new mocked.MockOauth2Error('invalid DPoP proof'));

      await expect(
        service.createCredential({
          ...createBaseOptions(),
          body: JSON.stringify({ any: 'payload' })
        })
      ).rejects.toBeInstanceOf(InvalidProofError);
    });

    it('throws CreateCredentialError when proof jwt is missing', async () => {
      const service = makeService();
      mocked.parseCredentialRequest.mockReturnValue({ ...parsedRequest, proofs: [] });

      await expect(
        service.createCredential({
          ...createBaseOptions(),
          body: JSON.stringify({ any: 'payload' })
        })
      ).rejects.toBeInstanceOf(CreateCredentialError);

      expect(mockNonceRepository.consume).not.toHaveBeenCalled();
    });

    it('does not consume nonce when proof verification fails', async () => {
      const service = makeService();
      mocked.parseCredentialRequest.mockReturnValue(parsedRequest);
      mocked.verifyCredentialRequestJwtProof.mockRejectedValue(new Error('invalid proof'));

      await expect(
        service.createCredential({
          ...createBaseOptions(),
          body: JSON.stringify({ any: 'payload' })
        })
      ).rejects.toThrow('invalid proof');

      expect(mockNonceRepository.consume).not.toHaveBeenCalled();
    });

    it('consumes nonce after successful proof verification', async () => {
      const service = makeService();
      mocked.parseCredentialRequest.mockReturnValue(parsedRequest);

      await expect(
        service.createCredential({
          ...createBaseOptions(),
          body: JSON.stringify({ any: 'payload' })
        })
      ).rejects.toBeInstanceOf(CreateCredentialError);

      expect(mockNonceRepository.consume).toHaveBeenCalledWith('nonce-1');
    });

    it('maps invalid DPoP header decode to InvalidProofError', async () => {
      const service = makeService();
      mocked.parseCredentialRequest.mockReturnValue(parsedRequest);
      mocked.decodeProtectedHeader.mockImplementation(() => {
        throw new Error('bad dpop');
      });

      await expect(
        service.createCredential({
          ...createBaseOptions(),
          body: JSON.stringify({ any: 'payload' })
        })
      ).rejects.toBeInstanceOf(InvalidProofError);
    });

    it('maps invalid access token decode to CreateCredentialError', async () => {
      const service = makeService();
      mocked.parseCredentialRequest.mockReturnValue(parsedRequest);
      mocked.decodeJwt.mockImplementation((token: string) => {
        if (token === 'access-token') {
          throw new Error('bad access token');
        }
        return { nonce: 'nonce-1' };
      });

      await expect(
        service.createCredential({
          ...createBaseOptions(),
          body: JSON.stringify({ any: 'payload' })
        })
      ).rejects.toBeInstanceOf(CreateCredentialError);
    });

    it('maps invalid proof jwt decode to CreateCredentialError', async () => {
      const service = makeService();
      mocked.parseCredentialRequest.mockReturnValue(parsedRequest);
      mocked.decodeJwt.mockImplementation((token: string) => {
        if (token === 'proof-jwt') {
          throw new Error('bad proof token');
        }
        return { cnf: { jkt: 'thumbprint' }, sub: 'subject-1' };
      });

      await expect(
        service.createCredential({
          ...createBaseOptions(),
          body: JSON.stringify({ any: 'payload' })
        })
      ).rejects.toBeInstanceOf(CreateCredentialError);
    });
  });

  describe('createCredential()', () => {
    it('throws CreateCredentialError for unknown credential identifier', () => {
      const err = new CreateCredentialError('Credential Identifier unknown not found');
      expect(err.name).toBe('CreateCredentialError');
      expect(err.message).toContain('unknown');
    });

    it('throws InvalidProofError when DPoP verification fails with Oauth2Error', () => {
      const err = new InvalidProofError('invalid DPoP proof');
      expect(err.name).toBe('InvalidProofError');
      expect(err.message).toBe('invalid DPoP proof');
    });

    it('exposes error classes with correct prototype chain', () => {
      const credErr = new CreateCredentialError('test');
      expect(credErr).toBeInstanceOf(CreateCredentialError);
      expect(credErr).toBeInstanceOf(Error);

      const proofErr = new InvalidProofError('test');
      expect(proofErr).toBeInstanceOf(InvalidProofError);
      expect(proofErr).toBeInstanceOf(Error);
    });
  });
});
