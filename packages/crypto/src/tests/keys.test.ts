import { describe, expect, it } from 'vitest';

import { generateKeyPair } from '../services/keys.js';

describe('keys service', () => {
  it('generates RSA key pair by default for sig/rsa', () => {
    const { privateKey, publicKey } = generateKeyPair({
      use: 'sig',
      keyType: 'rsa'
    });

    expect(privateKey.asymmetricKeyType).toBe('rsa');
    expect(publicKey.asymmetricKeyType).toBe('rsa');
  });

  it('generates EC key pair by default for sig/ec (ES256)', () => {
    const { privateKey, publicKey } = generateKeyPair({
      use: 'sig',
      keyType: 'ec'
    });

    expect(privateKey.asymmetricKeyType).toBe('ec');
    expect(publicKey.asymmetricKeyType).toBe('ec');

    const jwk = privateKey.export({ format: 'jwk' });
    expect(jwk).toMatchObject({ kty: 'EC', crv: 'P-256' });
  });

  it('generates Ed25519 key pair by default for sig/ed25519', () => {
    const { privateKey, publicKey } = generateKeyPair({
      use: 'sig',
      keyType: 'ed25519'
    });

    expect(privateKey.asymmetricKeyType).toBe('ed25519');
    expect(publicKey.asymmetricKeyType).toBe('ed25519');
  });

  it('generates RSA key pair by default for enc/rsa (RSA-OAEP-256)', () => {
    const { privateKey, publicKey } = generateKeyPair({
      use: 'enc',
      keyType: 'rsa'
    });

    expect(privateKey.asymmetricKeyType).toBe('rsa');
    expect(publicKey.asymmetricKeyType).toBe('rsa');
  });

  it('generates ECDH key pair by default for enc/ec (ECDH-ES)', () => {
    const { privateKey, publicKey } = generateKeyPair({
      use: 'enc',
      keyType: 'ec'
    });

    expect(privateKey.asymmetricKeyType).toBe('ec');
    expect(publicKey.asymmetricKeyType).toBe('ec');

    const jwk = privateKey.export({ format: 'jwk' });
    expect(jwk).toMatchObject({ kty: 'EC', crv: 'P-256' });
  });

  it('uses the requested curve for ECDH-ES+A256KW', () => {
    const { privateKey } = generateKeyPair({
      use: 'enc',
      keyType: 'ec',
      alg: 'ECDH-ES+A256KW',
      namedCurve: 'P-384'
    });

    const jwk = privateKey.export({ format: 'jwk' });
    expect(jwk).toMatchObject({ kty: 'EC', crv: 'P-384' });
  });

  it('rejects incompatible algorithm/keyType/use combinations', () => {
    expect(() =>
      generateKeyPair({
        use: 'enc',
        keyType: 'rsa',
        alg: 'ES256'
      })
    ).toThrow("Algorithm 'ES256' not valid for enc/rsa");
  });

  it('rejects unsupported algorithms for a valid key type', () => {
    expect(() =>
      generateKeyPair({
        use: 'sig',
        keyType: 'ec',
        alg: 'FOO-ALG'
      })
    ).toThrow("Algorithm 'FOO-ALG' not valid for sig/ec");
  });
});
