import { describe, expect, it, vi } from 'vitest';

import {
  CreateAccessTokenError,
  InvalidGrantError,
  TokenService,
  UnsupportedGrantTypeError
} from '../token-service.js';

import type { JwksRepository } from '../../signer.js';
import type { ITokenParRepository } from '../token-service.js';

function makeParLookup(overrides: Partial<ITokenParRepository> = {}): ITokenParRepository {
  return {
    consume: vi.fn().mockResolvedValue(undefined),
    getByCode: vi.fn().mockResolvedValue(undefined),
    ...overrides
  };
}

function makeJwksRepo(): JwksRepository {
  const fakeKey = { alg: 'ES256', crv: 'P-256', kid: 'test', kty: 'EC' as const, x: 'x', y: 'y' };
  const fakePrivKey = { ...fakeKey, d: 'd' };
  return {
    getEncrypt: vi.fn().mockReturnValue({ private: fakePrivKey, public: fakeKey }),
    getSign: vi.fn().mockReturnValue({ private: fakePrivKey, public: fakeKey }),
    iacaX509: vi.fn().mockReturnValue('')
  };
}

describe('TokenService', () => {
  describe('createAccessToken', () => {
    it('throws CreateAccessTokenError when required fields are missing', async () => {
      const svc = new TokenService(makeParLookup(), makeJwksRepo());

      await expect(
        svc.createAccessToken({
          baseURL: 'https://example.com',
          callbacks: { generateRandom: vi.fn(), hash: vi.fn(), signJwt: vi.fn() },
          config: { isVersion: vi.fn().mockReturnValue(false) } as never,
          tokenRequest: { bodyString: 'grant_type=authorization_code' }
        })
      ).rejects.toBeInstanceOf(CreateAccessTokenError);
    });

    it('throws UnsupportedGrantTypeError when grant_type is not authorization_code', async () => {
      const svc = new TokenService(makeParLookup(), makeJwksRepo());

      await expect(
        svc.createAccessToken({
          baseURL: 'https://example.com',
          callbacks: { generateRandom: vi.fn(), hash: vi.fn(), signJwt: vi.fn() },
          config: { isVersion: vi.fn().mockReturnValue(false) } as never,
          tokenRequest: {
            bodyString: 'code=abc&grant_type=refresh_token&redirect_uri=https%3A%2F%2Fclient.example.com'
          }
        })
      ).rejects.toBeInstanceOf(UnsupportedGrantTypeError);
    });

    it('throws InvalidGrantError when code not found', async () => {
      const svc = new TokenService(makeParLookup({ getByCode: vi.fn().mockResolvedValue(undefined) }), makeJwksRepo());

      await expect(
        svc.createAccessToken({
          baseURL: 'https://example.com',
          callbacks: { generateRandom: vi.fn(), hash: vi.fn(), signJwt: vi.fn() },
          config: { isVersion: vi.fn().mockReturnValue(false) } as never,
          tokenRequest: {
            bodyString: 'code=bad&grant_type=authorization_code&redirect_uri=https%3A%2F%2Fclient.example.com'
          }
        })
      ).rejects.toBeInstanceOf(InvalidGrantError);
    });

    it('throws InvalidGrantError when redirect_uri does not match', async () => {
      const parRequest = {
        authorization_details: [],
        client_id: 'client',
        redirect_uri: 'https://client.example.com/cb',
        request_uri: 'urn:test'
      };
      const lookup = makeParLookup({
        getByCode: vi.fn().mockResolvedValue({ parRequest, requestUri: 'urn:test' })
      });
      const svc = new TokenService(lookup, makeJwksRepo());

      await expect(
        svc.createAccessToken({
          baseURL: 'https://example.com',
          callbacks: { generateRandom: vi.fn(), hash: vi.fn(), signJwt: vi.fn() },
          config: { isVersion: vi.fn().mockReturnValue(false) } as never,
          tokenRequest: {
            bodyString: 'code=good&grant_type=authorization_code&redirect_uri=https%3A%2F%2Fwrong.example.com'
          }
        })
      ).rejects.toBeInstanceOf(InvalidGrantError);
    });
  });
});
