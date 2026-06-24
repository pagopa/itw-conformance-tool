import { exportJWK, generateKeyPair } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';
import { ZodError } from 'zod';

import { getIACAChain } from '../services/certificates.js';
import { isValidJwk, validateIACAKeyPair, validateJWKS } from '../services/validate.js';

type JwkRecord = Record<string, unknown>;

describe('isValidJwk', () => {
  let sigKey: JwkRecord;
  let encKey: JwkRecord;

  beforeAll(async () => {
    const [sigPair, encPair] = await Promise.all([
      generateKeyPair('ES256', { extractable: true }),
      generateKeyPair('ECDH-ES', { extractable: true })
    ]);

    const [sigJwk, encJwk] = await Promise.all([exportJWK(sigPair.privateKey), exportJWK(encPair.privateKey)]);

    sigKey = { ...sigJwk, kid: 'sig-valid', use: 'sig', alg: 'ES256', key_ops: ['sign'] };
    encKey = { ...encJwk, kid: 'enc-valid', use: 'enc', alg: 'ECDH-ES', key_ops: ['deriveKey'] };
  });

  it('returns true for a valid signing JWK', async () => {
    await expect(isValidJwk(sigKey)).resolves.toBe(true);
  });

  it('returns false for an invalid payload shape', async () => {
    await expect(isValidJwk('not-a-jwk')).resolves.toBe(false);
  });

  it('returns false for a non-signing JWK', async () => {
    await expect(isValidJwk(encKey)).resolves.toBe(false);
  });

  it('returns false when the JWK is structurally accepted but cryptographically incomplete', async () => {
    const incompleteEcKey = { ...sigKey };
    delete incompleteEcKey.x;

    await expect(isValidJwk(incompleteEcKey)).resolves.toBe(false);
  });
});

describe('validateJWKS', () => {
  let sigKey: JwkRecord;
  let encKey: JwkRecord;

  beforeAll(async () => {
    const [sigPair, encPair] = await Promise.all([
      generateKeyPair('ES256', { extractable: true }),
      generateKeyPair('ECDH-ES', { extractable: true })
    ]);

    const [sigJwk, encJwk] = await Promise.all([exportJWK(sigPair.privateKey), exportJWK(encPair.privateKey)]);

    sigKey = { ...sigJwk, kid: 'sig-1', use: 'sig', alg: 'ES256', key_ops: ['sign'] };
    encKey = { ...encJwk, kid: 'enc-1', use: 'enc', alg: 'ECDH-ES', key_ops: ['deriveKey'] };
  });

  it('accepts valid signing and encryption keys', async () => {
    await expect(validateJWKS({ keys: [sigKey, encKey] })).resolves.toBeUndefined();
  });

  it('rejects duplicate kids', async () => {
    await expect(
      validateJWKS({
        keys: [
          { ...sigKey, kid: 'dup' },
          { ...encKey, kid: 'dup' }
        ]
      })
    ).rejects.toThrow(/duplicate kid/i);
  });

  it('rejects enc key without alg hint', async () => {
    const noAlg = { ...encKey };
    delete noAlg.alg;

    await expect(validateJWKS({ keys: [{ ...noAlg, kid: 'enc-no-alg' }] })).rejects.toThrow();
  });

  it('rejects invalid payload shape', async () => {
    await expect(validateJWKS('not-an-object')).rejects.toThrow(ZodError);
  });
});

describe('validateIACAKeyPair', () => {
  it('accepts a matching cert and key pair', async () => {
    const iaca = await getIACAChain();

    await expect(validateIACAKeyPair(iaca.certificate, iaca.privateKey)).resolves.toBeUndefined();
  });

  it('rejects mismatched cert and key', async () => {
    const first = await getIACAChain();
    const second = await getIACAChain();

    await expect(validateIACAKeyPair(first.certificate, second.privateKey)).rejects.toThrow(
      'IACA certificate and private key do not correspond'
    );
  });
});
