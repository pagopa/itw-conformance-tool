import { beforeEach, describe, expect, it, vi } from 'vitest';

import { CreateCredentialError, CredentialService, InvalidProofError } from '../credential-service.js';

import type { JwksRepository } from '../../signer.js';
import type { INonceRepository } from '@itw-conformance-tool/database';

const mockNonceRepository: INonceRepository = {
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
  });

  describe('createCredential()', () => {
    it('throws CreateCredentialError when body is not valid JSON', async () => {
      const service = makeService();

      await expect(
        service.createCredential({
          baseURL: 'https://issuer.example',
          body: 'not-json',
          callbacks: { hash: vi.fn(), verifyJwt: vi.fn() },
          config: { isVersion: vi.fn().mockReturnValue(false) } as never,
          headers: new Headers(),
          method: 'POST',
          url: 'https://issuer.example/credential'
        })
      ).rejects.toThrow();
    });

    it('throws CreateCredentialError when parsed credential request is missing required fields', async () => {
      const service = makeService();

      await expect(
        service.createCredential({
          baseURL: 'https://issuer.example',
          body: JSON.stringify({}),
          callbacks: { hash: vi.fn(), verifyJwt: vi.fn() },
          config: { isVersion: vi.fn().mockReturnValue(false) } as never,
          headers: new Headers(),
          method: 'POST',
          url: 'https://issuer.example/credential'
        })
      ).rejects.toThrow();
    });

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
