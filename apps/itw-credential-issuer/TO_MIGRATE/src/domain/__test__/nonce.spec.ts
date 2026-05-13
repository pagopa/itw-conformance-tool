// generateNonce.test.ts

import { beforeEach, describe, expect, it, vi } from 'vitest';

import { NonceOptions, NonceRepository, generateNonce } from '../nonce';

describe('generateNonce', () => {
  let repo: NonceRepository;
  let options: NonceOptions;

  beforeEach(() => {
    repo = {
      delete: vi.fn().mockResolvedValue(undefined),
      get: vi.fn(),
      insert: vi.fn().mockImplementation((nonce) => Promise.resolve(nonce))
    };
    options = {
      nonceRepository: repo
    };
  });

  it('should generate a 64-char hex nonce and call insert with it', async () => {
    const nonceArg = await generateNonce(options);

    // The nonce should be 32 bytes (64 hex chars)
    expect(repo.insert).toHaveBeenCalledTimes(1);
    expect(typeof nonceArg).toBe('string');
    expect(nonceArg).toHaveLength(64);
    expect(nonceArg).toMatch(/^[a-f0-9]+$/);
  });
});
