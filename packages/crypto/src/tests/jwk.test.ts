import { describe, expect, it } from 'vitest';

import { generateConfigurableJwks, generateEcPrivateJwk, generateJWKS, generateSigningJwks } from '../services/jwk.js';

describe('jwk service', () => {
  it('generateEcPrivateJwk returns an ES256 key with descriptor metadata', () => {
    const jwks = generateEcPrivateJwk({
      alg: 'ES256',
      keyOps: ['sign'],
      kid: 'ec-kid-1',
      use: 'sig'
    });

    expect(jwks.keys).toHaveLength(1);
    const [key] = jwks.keys;

    expect(key['kty']).toBe('EC');
    expect(key['crv']).toBe('P-256');
    expect(key['kid']).toBe('ec-kid-1');
    expect(key['alg']).toBe('ES256');
    expect(key['use']).toBe('sig');
    expect(key['key_ops']).toEqual(['sign']);
  });

  it('generateEcPrivateJwk throws for unsupported EC algorithm', () => {
    expect(() =>
      generateEcPrivateJwk({
        alg: 'RS256' as never,
        keyOps: ['sign'],
        kid: 'bad-alg',
        use: 'sig'
      })
    ).toThrow("Algorithm 'RS256' not valid for sig/ec");
  });

  it('generateJWKS creates keys with default key_ops based on use and algorithm', async () => {
    const jwks = await generateJWKS({
      keys: [
        { alg: 'ES256', count: 2, use: 'sig' },
        { alg: 'ECDH-ES', count: 1, use: 'enc' }
      ]
    });

    expect(jwks.keys).toHaveLength(3);

    const sigKeys = jwks.keys.filter((key) => key['use'] === 'sig');
    const encKeys = jwks.keys.filter((key) => key['use'] === 'enc');

    expect(sigKeys).toHaveLength(2);
    expect(encKeys).toHaveLength(1);

    for (const key of sigKeys) {
      expect(key['key_ops']).toEqual(['sign']);
      expect(typeof key['kid']).toBe('string');
    }

    expect(encKeys[0]['key_ops']).toEqual(['deriveKey']);
  });

  it('generateJWKS rejects empty key specifications', async () => {
    await expect(generateJWKS({ keys: [] })).rejects.toThrow('generateJWKS requires at least one key specification');
  });

  it('generateJWKS rejects invalid key count', async () => {
    await expect(
      generateJWKS({
        keys: [{ alg: 'ES256', count: 0, use: 'sig' }]
      })
    ).rejects.toThrow('Invalid key count for alg ES256: count must be an integer >= 1');
  });

  it('generateJWKS rejects invalid key_ops for signing use', async () => {
    await expect(
      generateJWKS({
        keys: [{ alg: 'ES256', keyOps: ['decrypt'], use: 'sig' }]
      })
    ).rejects.toThrow('Invalid key_ops for use=sig and alg=ES256: decrypt');
  });

  it('generateJWKS rejects unknown key operation', async () => {
    await expect(
      generateJWKS({
        keys: [{ alg: 'ES256', keyOps: ['not-an-op'], use: 'sig' }]
      })
    ).rejects.toThrow('Unknown key operation: not-an-op');
  });

  it('generateSigningJwks returns a JwkSet with one RSA signing key', () => {
    const jwks = generateSigningJwks({ kid: 'issuer-signing-key', use: 'sig' });

    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]['alg']).toBe('RS256');
    expect(jwks.keys[0]['kid']).toBe('issuer-signing-key');
    expect(jwks.keys[0]['key_ops']).toEqual(['sign']);
  });

  it('generateConfigurableJwks returns a JwkSet', async () => {
    const jwks = await generateConfigurableJwks({
      keys: [{ alg: 'ES256', use: 'sig' }]
    });

    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]['alg']).toBe('ES256');
  });
});
