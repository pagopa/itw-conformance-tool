import { describe, expect, it } from 'vitest';

import {
  hasCompactJwtShape,
  hasNoPrivateJwkParams,
  isKeySemanticallyConsistent,
  isPublicSigningJwk,
  isValidPublicJwks
} from '../services/federation.js';
import { generateEcPrivateJwk } from '../services/jwk.js';

describe('federation helpers', () => {
  it('hasCompactJwtShape validates compact JWT format', () => {
    expect(hasCompactJwtShape('a.b.c')).toBe(true);
    expect(hasCompactJwtShape('a.b')).toBe(false);
    expect(hasCompactJwtShape('a..c')).toBe(false);
  });

  it('hasNoPrivateJwkParams detects private material', () => {
    expect(hasNoPrivateJwkParams({ kty: 'EC', kid: 'k1', x: 'x', y: 'y' })).toBe(true);
    expect(hasNoPrivateJwkParams({ kty: 'EC', kid: 'k1', d: 'secret' })).toBe(false);
  });

  it('isPublicSigningJwk accepts signing-only public keys', () => {
    expect(isPublicSigningJwk({ kty: 'EC', kid: 'k1', use: 'sig', key_ops: ['verify'] })).toBe(true);
    expect(isPublicSigningJwk({ kty: 'EC', kid: 'k1', use: 'enc' })).toBe(false);
  });

  it('isKeySemanticallyConsistent validates use/key_ops consistency', () => {
    expect(isKeySemanticallyConsistent({ use: 'sig', key_ops: ['sign', 'verify'] })).toBe(true);
    expect(isKeySemanticallyConsistent({ use: 'sig', key_ops: ['decrypt'] })).toBe(false);
    expect(isKeySemanticallyConsistent({ use: 'enc', key_ops: ['encrypt', 'decrypt'] })).toBe(true);
  });

  it('isValidPublicJwks returns false for private-key-only jwks', async () => {
    const privateJwkSet = generateEcPrivateJwk({
      alg: 'ES256',
      keyOps: ['sign'],
      kid: 'private-key',
      use: 'sig'
    });

    await expect(isValidPublicJwks(privateJwkSet)).resolves.toBe(false);
  });
});
