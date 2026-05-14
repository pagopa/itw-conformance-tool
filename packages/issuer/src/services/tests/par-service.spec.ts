import { describe, expect, it, vi } from 'vitest';

import { PAR_TTL_MS } from '../../models/par-entry.js';
import { PARService, PostPushedAuthorizationError } from '../par-service.js';

import type { IPARRepository, PAREntry } from '@itw-conformance-tool/database';

function makeRepo(overrides: Partial<IPARRepository> = {}): IPARRepository {
  return {
    delete: vi.fn().mockResolvedValue(undefined),
    get: vi.fn().mockResolvedValue(undefined),
    insert: vi.fn().mockResolvedValue(undefined),
    update: vi.fn().mockResolvedValue(undefined),
    ...overrides
  };
}

describe('PARService', () => {
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
      const expiresAt = Date.now() + 300_000;

      await svc.setCode('urn:test', code, expiresAt);

      expect(repo.update).toHaveBeenCalledOnce();
      const [, data] = (repo.update as ReturnType<typeof vi.fn>).mock.calls[0] as [string, Partial<PAREntry>];
      const updatedRequest = JSON.parse(data.requestObject ?? '{}');
      expect(updatedRequest.code).toBe(code);
      expect(updatedRequest.code_expires_at).toBe(expiresAt);
    });

    it('throws PostPushedAuthorizationError when entry not found', async () => {
      const repo = makeRepo({ get: vi.fn().mockResolvedValue(undefined) });
      const svc = new PARService(repo);

      await expect(svc.setCode('urn:missing', 'code', Date.now())).rejects.toBeInstanceOf(PostPushedAuthorizationError);
    });
  });
});
