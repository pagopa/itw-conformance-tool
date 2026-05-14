import { describe, expect, it } from 'vitest';

import { NONCE_TTL_MS, createNonce } from '../nonce.js';
import { PAR_TTL_MS } from '../par-entry.js';
import { STATUS_LIST_TTL_SECONDS } from '../status-list.js';
import { ACCESS_TOKEN_TTL_SECONDS, AUTHORIZATION_CODE_TTL_SECONDS } from '../token.js';

describe('Nonce model', () => {
  it('creates a nonce with default TTL', () => {
    const before = Date.now();
    const nonce = createNonce('abc');
    const after = Date.now();

    expect(nonce.value).toBe('abc');
    expect(nonce.expiresAt).toBeGreaterThanOrEqual(before + NONCE_TTL_MS);
    expect(nonce.expiresAt).toBeLessThanOrEqual(after + NONCE_TTL_MS);
  });

  it('creates a nonce with custom TTL', () => {
    const nonce = createNonce('xyz', 1000);
    expect(nonce.value).toBe('xyz');
    expect(nonce.expiresAt).toBeLessThanOrEqual(Date.now() + 1000 + 10);
  });

  it('NONCE_TTL_MS is 5 minutes', () => {
    expect(NONCE_TTL_MS).toBe(300_000);
  });
});

describe('ParEntry model', () => {
  it('PAR_TTL_MS is 60 seconds', () => {
    expect(PAR_TTL_MS).toBe(60_000);
  });

  it('AUTHORIZATION_CODE_TTL_SECONDS is 5 minutes (from token model)', () => {
    expect(AUTHORIZATION_CODE_TTL_SECONDS).toBe(300);
  });
});

describe('Token model', () => {
  it('ACCESS_TOKEN_TTL_SECONDS is 5 minutes', () => {
    expect(ACCESS_TOKEN_TTL_SECONDS).toBe(300);
  });

  it('AUTHORIZATION_CODE_TTL_SECONDS is 5 minutes', () => {
    expect(AUTHORIZATION_CODE_TTL_SECONDS).toBe(300);
  });
});

describe('StatusList model', () => {
  it('STATUS_LIST_TTL_SECONDS is 1 hour', () => {
    expect(STATUS_LIST_TTL_SECONDS).toBe(3600);
  });
});
