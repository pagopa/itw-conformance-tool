import { createPublicKey, generateKeyPairSync } from 'node:crypto';

import {
  compactDecrypt,
  decodeProtectedHeader,
  exportJWK,
  exportPKCS8,
  generateKeyPair,
  importPKCS8,
  importJWK,
  jwtVerify,
  SignJWT
} from 'jose';
import { describe, expect, it } from 'vitest';

import {
  createDecryptJweCallback,
  createEncryptJweCallback,
  createSignJwtCallback,
  createVerifyJwtCallback
} from '../services/callbacks.js';

describe('callbacks service', () => {
  it('createSignJwtCallback signs JWT with jwk method using auth request key', async () => {
    const { privateKey, publicKey } = await generateKeyPair('RS256');
    const privatePem = await exportPKCS8(privateKey);
    const publicJwk = await exportJWK(publicKey);

    const signCallback = createSignJwtCallback(privatePem, privatePem);
    const result = await signCallback(
      {
        alg: 'RS256',
        method: 'jwk',
        publicJwk
      } as never,
      {
        header: { typ: 'JWT' },
        payload: { sub: 'alice' }
      } as never
    );

    expect(result.signerJwk).toEqual(publicJwk);

    const publicKeyForVerify = await importJWK(publicJwk, 'RS256');
    const verified = await jwtVerify(result.jwt, publicKeyForVerify, { algorithms: ['RS256'] });
    expect(verified.payload.sub).toBe('alice');
  });

  it('createSignJwtCallback uses signing key for non-jwk methods', async () => {
    const authPair = await generateKeyPair('RS256');
    const signingPair = await generateKeyPair('RS256');

    const authPrivatePem = await exportPKCS8(authPair.privateKey);
    const signingPrivatePem = await exportPKCS8(signingPair.privateKey);
    const authPublicJwk = await exportJWK(authPair.publicKey);
    const signingPublicJwk = await exportJWK(signingPair.publicKey);

    const signCallback = createSignJwtCallback(authPrivatePem, signingPrivatePem);
    const result = await signCallback(
      {
        alg: 'RS256',
        method: 'x5c',
        publicJwk: authPublicJwk
      } as never,
      {
        header: { typ: 'JWT' },
        payload: { aud: 'wallet' }
      } as never
    );

    const signingPublicKey = await importJWK(signingPublicJwk, 'RS256');
    const verified = await jwtVerify(result.jwt, signingPublicKey, { algorithms: ['RS256'] });
    expect(verified.payload.aud).toBe('wallet');

    const authPublicKey = await importJWK(authPublicJwk, 'RS256');
    await expect(jwtVerify(result.jwt, authPublicKey, { algorithms: ['RS256'] })).rejects.toThrow();
  });

  it('createVerifyJwtCallback verifies compact JWT when method is jwk', async () => {
    const { privateKey, publicKey } = await generateKeyPair('ES256');
    const publicJwk = await exportJWK(publicKey);

    const compact = await new SignJWT({ nonce: '123' })
      .setProtectedHeader({ alg: 'ES256', typ: 'JWT' })
      .sign(privateKey);

    const verifyCallback = createVerifyJwtCallback();
    const result = await verifyCallback(
      {
        alg: 'ES256',
        method: 'jwk',
        publicJwk
      } as never,
      { compact } as never
    );

    expect(result.verified).toBe(true);
    expect(result.signerJwk).toEqual(publicJwk);
  });

  it('createVerifyJwtCallback returns false for non-jwk methods', async () => {
    const verifyCallback = createVerifyJwtCallback();

    const result = await verifyCallback(
      {
        alg: 'ES256',
        method: 'x5c',
        publicJwk: { kty: 'EC' }
      } as never,
      { compact: 'header.payload.signature' } as never
    );

    expect(result).toEqual({ verified: false });
  });

  it('createVerifyJwtCallback returns false for invalid jwt', async () => {
    const { publicKey } = await generateKeyPair('ES256');
    const publicJwk = await exportJWK(publicKey);

    const verifyCallback = createVerifyJwtCallback();
    const result = await verifyCallback(
      {
        alg: 'ES256',
        method: 'jwk',
        publicJwk
      } as never,
      { compact: 'invalid.token.value' } as never
    );

    expect(result).toEqual({ signerJwk: publicJwk, verified: false });
  });

  it('createEncryptJweCallback encrypts payload with ECDH-ES and expected headers', async () => {
    const { privateKey: privatePem, publicKey: publicPem } = generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
      privateKeyEncoding: { format: 'pem', type: 'pkcs8' },
      publicKeyEncoding: { format: 'pem', type: 'spki' }
    });
    const publicJwk = await exportJWK(createPublicKey(publicPem));

    const encryptCallback = createEncryptJweCallback();

    const plaintext = 'sensitive payload';
    const encrypted = await encryptCallback(
      {
        alg: 'ECDH-ES',
        enc: 'A256GCM',
        publicJwk
      } as never,
      plaintext
    );

    expect(typeof encrypted.jwe).toBe('string');
    expect(encrypted.encryptionJwk).toEqual(publicJwk);

    const header = decodeProtectedHeader(encrypted.jwe);
    expect(header.alg).toBe('ECDH-ES');
    expect(header.enc).toBe('A256GCM');

    const privateKey = await importPKCS8(privatePem, 'ECDH-ES');
    const { plaintext: decryptedBytes } = await compactDecrypt(encrypted.jwe, privateKey);
    expect(new TextDecoder().decode(decryptedBytes)).toBe(plaintext);
  });

  it('createDecryptJweCallback returns false when key is not valid for payload', async () => {
    const firstPair = await generateKeyPair('ECDH-ES');
    const secondPair = await generateKeyPair('ECDH-ES');
    const firstPublicJwk = await exportJWK(firstPair.publicKey);

    const encryptCallback = createEncryptJweCallback();
    const wrongPrivatePem = await exportPKCS8(secondPair.privateKey);
    const decryptCallback = createDecryptJweCallback(wrongPrivatePem);

    const encrypted = await encryptCallback(
      {
        alg: 'ECDH-ES',
        enc: 'A256GCM',
        publicJwk: firstPublicJwk
      } as never,
      'payload'
    );

    await expect(decryptCallback(encrypted.jwe)).resolves.toEqual({ decrypted: false });
  });
});
