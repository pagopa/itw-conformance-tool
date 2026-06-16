import { describe, expect, it } from 'vitest';

import { getAuthRequestKey, getAuthResponseKey, getSigningKeys } from '../../utils/crypto.js';

type JwkRecord = Record<string, unknown>;

describe('cli crypto utils', () => {
  it('getSigningKeys returns issuer-compatible ES256 and ECDH-ES EC keys', () => {
    const jwks = JSON.parse(getSigningKeys()) as { keys?: JwkRecord[] };

    expect(Array.isArray(jwks.keys)).toBe(true);
    expect(jwks.keys).toHaveLength(2);

    const signing = jwks.keys?.find((key) => key.use === 'sig');
    const encryption = jwks.keys?.find((key) => key.use === 'enc');

    expect(signing?.kty).toBe('EC');
    expect(signing?.alg).toBe('ES256');
    expect(signing?.key_ops).toEqual(['sign']);

    expect(encryption?.kty).toBe('EC');
    expect(encryption?.alg).toBe('ECDH-ES');
    expect(encryption?.key_ops).toEqual(['deriveKey']);
  });

  it('getAuthRequestKey returns an ES256 EC private key', () => {
    const key = JSON.parse(getAuthRequestKey()) as JwkRecord;

    expect(key.kty).toBe('EC');
    expect(key.alg).toBe('ES256');
    expect(key.use).toBe('sig');
    expect(key.key_ops).toEqual(['sign']);
    expect(typeof key.d).toBe('string');
  });

  it('getAuthResponseKey returns an ECDH-ES EC private key', () => {
    const key = JSON.parse(getAuthResponseKey()) as JwkRecord;

    expect(key.kty).toBe('EC');
    expect(key.alg).toBe('ECDH-ES');
    expect(key.use).toBe('enc');
    expect(key.key_ops).toEqual(['deriveKey']);
    expect(typeof key.d).toBe('string');
  });
});
