import { describe, expect, it, vi } from 'vitest';

import { PAR_TTL_MS } from '../../models/par-entry.js';
import { PARService, PostPushedAuthorizationError } from '../par-service.js';

import type { IPARRepository, PAREntry } from '@itw-conformance-tool/database';

const { parsePushedAuthorizationRequestMock } = vi.hoisted(() => ({
  parsePushedAuthorizationRequestMock: vi.fn()
}));

vi.mock('@pagopa/io-wallet-oauth2', () => ({
  parsePushedAuthorizationRequest: parsePushedAuthorizationRequestMock
}));

vi.mock('../../z-par.js', () => ({
  getPushedAuthorizationRequestSchema: vi.fn().mockReturnValue({
    parse: vi.fn((value) => value)
  })
}));

function makeRepo(overrides: Partial<IPARRepository> = {}): IPARRepository {
  return {
    delete: vi.fn().mockResolvedValue(undefined),
    get: vi.fn().mockResolvedValue(undefined),
    getByMrtdAuthSession: vi.fn().mockResolvedValue(undefined),
    insert: vi.fn().mockResolvedValue(undefined),
    update: vi.fn().mockResolvedValue(undefined),
    ...overrides
  };
}

describe('PARService', () => {
  describe('parseAndStore', () => {
    it('stores the PAR request and returns a request_uri', async () => {
      const repo = makeRepo();
      const svc = new PARService(repo);

      parsePushedAuthorizationRequestMock.mockResolvedValue({
        authorizationRequest: {
          client_id: 'client',
          redirect_uri: 'https://wallet.example/callback'
        },
        authorizationRequestJwt: 'signed-jwt'
      });

      const requestUri = await svc.parseAndStore({
        baseURL: 'https://issuer.example',
        callbacks: { fetch: vi.fn() },
        config: { isVersion: vi.fn().mockReturnValue(false) } as never,
        parRequest: {
          bodyString: 'client_id=client&request=signed-jwt',
          headers: new Headers(),
          method: 'POST' as never,
          url: 'https://issuer.example/par'
        }
      });

      expect(requestUri).toMatch(/^urn:ietf:params:oauth:request_uri:/);
      expect(repo.insert).toHaveBeenCalledOnce();
      const [inserted] = (repo.insert as ReturnType<typeof vi.fn>).mock.calls[0] as [PAREntry];
      expect(inserted.clientId).toBe('client');
      expect(inserted.requestUri).toBe(requestUri);
      expect(inserted.expiresAt).toBeGreaterThanOrEqual(Date.now());

      const savedRequest = JSON.parse(inserted.requestObject) as Record<string, unknown>;
      expect(savedRequest.id).toBeTypeOf('string');
      expect(savedRequest.request_uri).toBe(requestUri);
    });

    it('throws when the signed authorization request is missing after parsing', async () => {
      const repo = makeRepo();
      const svc = new PARService(repo);

      parsePushedAuthorizationRequestMock.mockResolvedValue({
        authorizationRequest: { client_id: 'client' },
        authorizationRequestJwt: undefined
      });

      await expect(
        svc.parseAndStore({
          baseURL: 'https://issuer.example',
          callbacks: { fetch: vi.fn() },
          config: { isVersion: vi.fn().mockReturnValue(false) } as never,
          parRequest: {
            bodyString: 'client_id=client&request=signed-jwt',
            headers: new Headers(),
            method: 'POST' as never,
            url: 'https://issuer.example/par'
          }
        })
      ).rejects.toBeInstanceOf(PostPushedAuthorizationError);
    });
  });

  describe('getByRequestUri', () => {
    it('returns the parsed par request when found', async () => {
      const parRequest = { id: '123', request_uri: 'urn:test', client_id: 'client' };
      const entry: PAREntry = {
        clientId: 'client',
        expiresAt: Date.now() + PAR_TTL_MS,
        requestObject: JSON.stringify(parRequest),
        requestUri: 'urn:test'
      };
      const repo = makeRepo({ get: vi.fn().mockResolvedValue(entry) });
      const svc = new PARService(repo);

      const result = await svc.getByRequestUri('urn:test');

      expect(result).toEqual(parRequest);
      expect(repo.get).toHaveBeenCalledWith('urn:test');
    });

    it('throws PostPushedAuthorizationError when not found', async () => {
      const repo = makeRepo({ get: vi.fn().mockResolvedValue(undefined) });
      const svc = new PARService(repo);

      await expect(svc.getByRequestUri('urn:missing')).rejects.toBeInstanceOf(PostPushedAuthorizationError);
    });
  });

  describe('setCode', () => {
    it('updates the request object with code', async () => {
      const parRequest = { id: '123', request_uri: 'urn:test', client_id: 'client' };
      const entry: PAREntry = {
        clientId: 'client',
        expiresAt: Date.now() + PAR_TTL_MS,
        requestObject: JSON.stringify(parRequest),
        requestUri: 'urn:test'
      };
      const repo = makeRepo({ get: vi.fn().mockResolvedValue(entry) });
      const svc = new PARService(repo);
      const code = 'auth-code-123';
      const expiresAtSeconds = Math.floor(Date.now() / 1000) + 300;

      await svc.setCode('urn:test', code, expiresAtSeconds);

      expect(repo.update).toHaveBeenCalledOnce();
      const [, data] = (repo.update as ReturnType<typeof vi.fn>).mock.calls[0] as [string, Partial<PAREntry>];
      const updatedRequest = JSON.parse(data.requestObject ?? '{}');
      expect(updatedRequest.code).toBe(code);
      expect(updatedRequest.code_expires_at).toBe(expiresAtSeconds);
    });

    it('throws PostPushedAuthorizationError when entry not found', async () => {
      const repo = makeRepo({ get: vi.fn().mockResolvedValue(undefined) });
      const svc = new PARService(repo);

      await expect(svc.setCode('urn:missing', 'code', Date.now())).rejects.toBeInstanceOf(PostPushedAuthorizationError);
    });
  });
});
