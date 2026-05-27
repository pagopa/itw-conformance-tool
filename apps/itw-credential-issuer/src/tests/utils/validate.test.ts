import { exportJWK, generateKeyPair, type JWK } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';
import { ZodError } from 'zod';

import { generateIaca } from '../../crypto/auto-keygen.js';
import { validateIACAKeyPair, validateJWKS } from '../../utils/validate.js';

/** Minimal valid sig key — generated once for all tests. */
let sigKey: JWK;
/** Minimal valid enc key (ECDH-ES) — generated once for all tests. */
let encKey: JWK;

beforeAll(async () => {
  const [sigPair, encPair] = await Promise.all([
    generateKeyPair('ES256', { extractable: true }),
    generateKeyPair('ECDH-ES', { extractable: true })
  ]);
  const [sigJwk, encJwk] = await Promise.all([exportJWK(sigPair.privateKey), exportJWK(encPair.privateKey)]);
  sigKey = { ...sigJwk, kid: 'sig-1', use: 'sig', alg: 'ES256', key_ops: ['sign'] };
  encKey = { ...encJwk, kid: 'enc-1', use: 'enc', alg: 'ECDH-ES', key_ops: ['deriveKey'] };
});

describe('validateJWKS', () => {
  describe('valid JWKS', () => {
    it('accepts a JWKS with a single signing key', async () => {
      await expect(validateJWKS({ keys: [sigKey] })).resolves.toBeUndefined();
    });

    it('accepts a JWKS with a sig key and an enc key', async () => {
      await expect(validateJWKS({ keys: [sigKey, encKey] })).resolves.toBeUndefined();
    });

    it('accepts a key with extra unknown fields (looseObject)', async () => {
      const keyWithExtras = { ...sigKey, kid: 'sig-extra', x5t: 'abc', customField: 42 };
      await expect(validateJWKS({ keys: [keyWithExtras] })).resolves.toBeUndefined();
    });

    it('accepts a key without optional use/alg/key_ops fields', async () => {
      const { use: _use, alg: _alg, key_ops: _ops, ...bare } = sigKey;
      await expect(validateJWKS({ keys: [{ ...bare, kid: 'bare-key' }] })).resolves.toBeUndefined();
    });
  });

  describe('structural errors (ZodError)', () => {
    it('rejects a non-object input', async () => {
      await expect(validateJWKS('not-an-object')).rejects.toThrow(ZodError);
    });

    it('rejects null', async () => {
      await expect(validateJWKS(null)).rejects.toThrow(ZodError);
    });

    it('rejects a JWKS without a keys array', async () => {
      await expect(validateJWKS({})).rejects.toThrow(ZodError);
    });

    it('rejects an empty keys array', async () => {
      await expect(validateJWKS({ keys: [] })).rejects.toThrow(ZodError);
    });

    it('rejects a key missing kty', async () => {
      const { kty: _kty, ...noKty } = sigKey;
      await expect(validateJWKS({ keys: [noKty] })).rejects.toThrow(ZodError);
    });

    it('rejects a key with an empty kid', async () => {
      await expect(validateJWKS({ keys: [{ ...sigKey, kid: '' }] })).rejects.toThrow(ZodError);
    });

    it('rejects a key with an invalid use value', async () => {
      await expect(validateJWKS({ keys: [{ ...sigKey, use: 'verify' }] })).rejects.toThrow(ZodError);
    });
  });

  describe('semantic errors', () => {
    it('rejects a JWKS with duplicate kid values', async () => {
      const dup = { ...encKey, kid: sigKey.kid }; // same kid as sigKey
      await expect(validateJWKS({ keys: [sigKey, dup] })).rejects.toThrow(/duplicate kid/i);
    });
  });

  describe('cryptographic errors', () => {
    it('rejects a key with malformed EC coordinates', async () => {
      const malformed: JWK = {
        kty: 'EC',
        crv: 'P-256',
        x: 'not-valid-base64url!!!',
        y: 'not-valid-base64url!!!',
        kid: 'bad-key',
        alg: 'ES256'
      };
      await expect(validateJWKS({ keys: [malformed] })).rejects.toThrow();
    });

    it('rejects an enc key when the alg hint is missing and the key cannot be inferred', async () => {
      // ECDH-ES key without alg — jose cannot determine the algorithm without a hint
      const { alg: _alg, ...noAlg } = encKey;
      await expect(validateJWKS({ keys: [{ ...noAlg, kid: 'enc-no-alg' }] })).rejects.toThrow();
    });
  });
});

describe('validateIACAKeyPair', () => {
  let certPem: string;
  let keyPem: string;

  beforeAll(async () => {
    ({ certPem, keyPem } = await generateIaca());
  });

  it('resolves for a valid matching cert and key', async () => {
    await expect(validateIACAKeyPair(certPem, keyPem)).resolves.toBeUndefined();
  });

  it('rejects when the certificate PEM is malformed', async () => {
    await expect(validateIACAKeyPair('not-a-pem', keyPem)).rejects.toThrow();
  });

  it('rejects when the private key PEM is malformed', async () => {
    await expect(validateIACAKeyPair(certPem, 'not-a-pem')).rejects.toThrow();
  });

  it('rejects when cert and key are from different pairs', async () => {
    const { keyPem: otherKeyPem } = await generateIaca();
    await expect(validateIACAKeyPair(certPem, otherKeyPem)).rejects.toThrow(
      'IACA certificate and private key do not correspond'
    );
  });
});
