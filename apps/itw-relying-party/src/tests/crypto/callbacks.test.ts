import { generateKeyPair, exportPKCS8, exportJWK, CompactEncrypt, importJWK } from 'jose';
import { describe, expect, it, beforeAll } from 'vitest';

import {
  createDecryptJweCallback,
  createEncryptJweCallback,
  createSignJwtCallback,
  createVerifyJwtCallback,
  generateRandomCallback,
  hashCallback
} from '../../crypto/callbacks.js';

import type { HashAlgorithm, JwtSignerJwk } from '@pagopa/io-wallet-oauth2';

let authRequestPem: string;
let signingPem: string;
let authResponsePem: string;

let authRequestPublicJwk: Record<string, unknown>;

beforeAll(async () => {
  const authRequestKeyPair = await generateKeyPair('ES256');
  authRequestPem = await exportPKCS8(authRequestKeyPair.privateKey);
  authRequestPublicJwk = await exportJWK(authRequestKeyPair.publicKey);

  const signingKeyPair = await generateKeyPair('ES256');
  signingPem = await exportPKCS8(signingKeyPair.privateKey);

  const authResponseKeyPair = await generateKeyPair('ECDH-ES', { crv: 'P-256' });
  authResponsePem = await exportPKCS8(authResponseKeyPair.privateKey);
});

describe('hashCallback', () => {
  it('produces a non-empty SHA-256 digest', () => {
    const data = new TextEncoder().encode('hello');
    const digest = hashCallback(data, 'sha-256' as HashAlgorithm);
    expect(digest).toBeInstanceOf(Uint8Array);
    expect(digest.length).toBe(32);
  });

  it('produces a non-empty SHA-384 digest', () => {
    const data = new TextEncoder().encode('hello');
    const digest = hashCallback(data, 'sha-384' as HashAlgorithm);
    expect(digest.length).toBe(48);
  });

  it('produces a non-empty SHA-512 digest', () => {
    const data = new TextEncoder().encode('hello');
    const digest = hashCallback(data, 'sha-512' as HashAlgorithm);
    expect(digest.length).toBe(64);
  });

  it('throws for unsupported algorithms', () => {
    const data = new TextEncoder().encode('hello');
    expect(() => hashCallback(data, 'md5' as HashAlgorithm)).toThrow('Unsupported hash algorithm: md5');
  });

  it('different inputs produce different digests', () => {
    const a = hashCallback(new TextEncoder().encode('foo'), 'sha-256' as HashAlgorithm);
    const b = hashCallback(new TextEncoder().encode('bar'), 'sha-256' as HashAlgorithm);
    expect(Buffer.from(a).toString('hex')).not.toBe(Buffer.from(b).toString('hex'));
  });
});

describe('generateRandomCallback', () => {
  it('returns a Uint8Array of the requested length', () => {
    const bytes = generateRandomCallback(32);
    expect(bytes).toBeInstanceOf(Uint8Array);
    expect(bytes.length).toBe(32);
  });

  it('successive calls produce different values', () => {
    const a = generateRandomCallback(16);
    const b = generateRandomCallback(16);
    expect(Buffer.from(a).toString('hex')).not.toBe(Buffer.from(b).toString('hex'));
  });
});

describe('createSignJwtCallback', () => {
  it('signs a JWT with method: jwk and returns the signer JWK', async () => {
    const signJwt = createSignJwtCallback(authRequestPem, signingPem);
    const signer: JwtSignerJwk = {
      method: 'jwk',
      alg: 'ES256',
      publicJwk: authRequestPublicJwk as JwtSignerJwk['publicJwk']
    };

    const result = await signJwt(signer, {
      header: { alg: 'ES256', typ: 'JWT' },
      payload: { iss: 'test', aud: 'audience', iat: Math.floor(Date.now() / 1000) }
    });

    expect(result.jwt).toMatch(/^[\w-]+\.[\w-]+\.[\w-]+$/);
    expect(result.signerJwk).toMatchObject({ kty: 'EC', crv: 'P-256' });
    expect(result.signerJwk).not.toHaveProperty('d');
  });

  it('signs a JWT with method: x5c and returns a public JWK (no private fields)', async () => {
    const signJwt = createSignJwtCallback(authRequestPem, signingPem);

    const result = await signJwt(
      { method: 'x5c', alg: 'ES256', x5c: [] },
      {
        header: { alg: 'ES256', typ: 'JWT' },
        payload: { iss: 'test' }
      }
    );

    expect(result.jwt).toMatch(/^[\w-]+\.[\w-]+\.[\w-]+$/);
    expect(result.signerJwk).toMatchObject({ kty: 'EC' });
    expect(result.signerJwk).not.toHaveProperty('d');
  });
});

describe('createVerifyJwtCallback', () => {
  it('verifies a valid JWT signed with the embedded public JWK', async () => {
    const signJwt = createSignJwtCallback(authRequestPem, signingPem);
    const verifyJwt = createVerifyJwtCallback();

    const signer: JwtSignerJwk = {
      method: 'jwk',
      alg: 'ES256',
      publicJwk: authRequestPublicJwk as JwtSignerJwk['publicJwk']
    };

    const { jwt } = await signJwt(signer, {
      header: { alg: 'ES256', typ: 'JWT' },
      payload: { iss: 'test' }
    });

    const [headerB64, payloadB64] = jwt.split('.');
    const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString());
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());

    const result = await verifyJwt(signer, { header, payload, compact: jwt });
    expect(result.verified).toBe(true);
  });

  it('returns verified: false for non-jwk methods', async () => {
    const verifyJwt = createVerifyJwtCallback();
    const result = await verifyJwt(
      { method: 'x5c', alg: 'ES256', x5c: [] },
      { header: { alg: 'ES256' }, payload: {}, compact: 'fake.jwt.token' }
    );
    expect(result.verified).toBe(false);
  });

  it('returns verified: false for tampered JWT', async () => {
    const signJwt = createSignJwtCallback(authRequestPem, signingPem);
    const verifyJwt = createVerifyJwtCallback();

    const signer: JwtSignerJwk = {
      method: 'jwk',
      alg: 'ES256',
      publicJwk: authRequestPublicJwk as JwtSignerJwk['publicJwk']
    };

    const { jwt } = await signJwt(signer, {
      header: { alg: 'ES256', typ: 'JWT' },
      payload: { iss: 'test' }
    });

    const [h, p] = jwt.split('.');
    const tampered = `${h}.${p}.invalidsignature`;
    const [headerB64, payloadB64] = tampered.split('.');
    const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString());
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());

    const result = await verifyJwt(signer, { header, payload, compact: tampered });
    expect(result.verified).toBe(false);
  });
});

describe('createDecryptJweCallback', () => {
  it('decrypts a JWE encrypted to the auth-response key', async () => {
    const authResponseKeyPair = await generateKeyPair('ECDH-ES', { crv: 'P-256' });
    const publicJwk = await exportJWK(authResponseKeyPair.publicKey);
    const recipientPublicKey = await importJWK(publicJwk, 'ECDH-ES');

    const plaintext = 'secret payload';
    const jwe = await new CompactEncrypt(new TextEncoder().encode(plaintext))
      .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
      .encrypt(recipientPublicKey);

    const localPem = await exportPKCS8(authResponseKeyPair.privateKey);
    const localDecrypt = createDecryptJweCallback(localPem);
    const result = await localDecrypt(jwe);

    expect(result.decrypted).toBe(true);
    if (result.decrypted) {
      expect(result.payload).toBe(plaintext);
      expect(result.decryptionJwk).not.toHaveProperty('d');
    }
  });

  it('returns decrypted: false for invalid JWE', async () => {
    const decryptJwe = createDecryptJweCallback(authResponsePem);
    const result = await decryptJwe('invalid.jwe.token.here.oops');
    expect(result.decrypted).toBe(false);
  });
});

describe('createEncryptJweCallback', () => {
  it('encrypts data and the result can be decrypted', async () => {
    const encryptJwe = createEncryptJweCallback();

    const recipientKeyPair = await generateKeyPair('ECDH-ES', { crv: 'P-256' });
    const recipientPublicJwk = await exportJWK(recipientKeyPair.publicKey);
    const recipientPem = await exportPKCS8(recipientKeyPair.privateKey);

    const plaintext = 'encrypted payload';
    const result = await encryptJwe(
      {
        method: 'jwk',
        alg: 'ECDH-ES',
        enc: 'A256GCM',
        publicJwk: recipientPublicJwk as JwtSignerJwk['publicJwk']
      },
      plaintext
    );

    expect(result.jwe).toBeTruthy();
    expect(result.encryptionJwk).toMatchObject({ kty: 'EC', crv: 'P-256' });
    expect(result.encryptionJwk).not.toHaveProperty('d');

    const decryptJwe = createDecryptJweCallback(recipientPem);
    const decryptResult = await decryptJwe(result.jwe);
    expect(decryptResult.decrypted).toBe(true);
    if (decryptResult.decrypted) {
      expect(decryptResult.payload).toBe(plaintext);
    }
  });

  it('includes apu and apv in the protected header when provided', async () => {
    const encryptJwe = createEncryptJweCallback();

    const recipientKeyPair = await generateKeyPair('ECDH-ES', { crv: 'P-256' });
    const recipientPublicJwk = await exportJWK(recipientKeyPair.publicKey);
    const apu = Buffer.from('party-u').toString('base64url');
    const apv = Buffer.from('party-v').toString('base64url');

    const result = await encryptJwe(
      {
        method: 'jwk',
        alg: 'ECDH-ES',
        enc: 'A256GCM',
        publicJwk: recipientPublicJwk as JwtSignerJwk['publicJwk'],
        apu,
        apv
      },
      'test'
    );

    const [protectedHeaderB64] = result.jwe.split('.');
    const header = JSON.parse(Buffer.from(protectedHeaderB64, 'base64url').toString());
    expect(header.apu).toBe(apu);
    expect(header.apv).toBe(apv);
  });
});
