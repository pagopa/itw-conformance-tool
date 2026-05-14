import { describe, expect, it, vi } from 'vitest';

import { NONCE_TTL_MS } from '../../models/nonce.js';
import { InvalidNonceError, NonceService } from '../nonce-service.js';

import type { INonceRepository } from '@itw-conformance-tool/database';

function makeRepo(overrides: Partial<INonceRepository> = {}): INonceRepository {
  return {
    consume: vi.fn().mockResolvedValue(false),
    delete: vi.fn().mockResolvedValue(undefined),
    get: vi.fn().mockResolvedValue(undefined),
    insert: vi.fn().mockResolvedValue(undefined),
    ...overrides
  };
}

describe('NonceService', () => {
  describe('generate', () => {
    it('inserts a nonce and returns it', async () => {
      const repo = makeRepo();
      const svc = new NonceService(repo);

      const nonce = await svc.generate();

      expect(nonce).toMatch(/^[0-9a-f]{64}$/);
      expect(repo.insert).toHaveBeenCalledOnce();
      const [value, expiresAt] = (repo.insert as ReturnType<typeof vi.fn>).mock.calls[0] as [string, number];
      expect(value).toBe(nonce);
      expect(expiresAt).toBeGreaterThanOrEqual(Date.now());
      expect(expiresAt).toBeLessThanOrEqual(Date.now() + NONCE_TTL_MS + 100);
    });

    it('uses the provided TTL', async () => {
      const repo = makeRepo();
      const svc = new NonceService(repo);
      const ttl = 1000;
      const before = Date.now();

      await svc.generate(ttl);

      const [, expiresAt] = (repo.insert as ReturnType<typeof vi.fn>).mock.calls[0] as [string, number];
      expect(expiresAt).toBeGreaterThanOrEqual(before + ttl);
    });
  });

  describe('consume', () => {
    it('consumes the nonce when found', async () => {
      const value = 'abc123';
      const repo = makeRepo({ consume: vi.fn().mockResolvedValue(true) });
      const svc = new NonceService(repo);

      await svc.consume(value);

      expect(repo.consume).toHaveBeenCalledWith(value);
    });

    it('throws InvalidNonceError when nonce not found', async () => {
      const repo = makeRepo({ consume: vi.fn().mockResolvedValue(false) });
      const svc = new NonceService(repo);

      await expect(svc.consume('unknown')).rejects.toBeInstanceOf(InvalidNonceError);
      expect(repo.consume).toHaveBeenCalledWith('unknown');
    });
  });
});
