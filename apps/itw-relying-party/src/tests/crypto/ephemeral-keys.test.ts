import { KeyObject } from 'node:crypto';

import { CompactEncrypt, compactDecrypt, importJWK } from 'jose';
import { describe, expect, it } from 'vitest';

import { generateEphemeralKeyPair } from '../../crypto/ephemeral-keys.js';

describe('generateEphemeralKeyPair', () => {
  it('returns a privateKey and a publicJwk', async () => {
    const { privateKey, publicJwk } = await generateEphemeralKeyPair();

    expect(privateKey).toBeTruthy();
    expect(publicJwk).toBeTruthy();
  });

  it('publicJwk has alg set to ECDH-ES', async () => {
    const { publicJwk } = await generateEphemeralKeyPair();
    expect(publicJwk.alg).toBe('ECDH-ES');
  });

  it('publicJwk has use set to enc', async () => {
    const { publicJwk } = await generateEphemeralKeyPair();
    expect(publicJwk.use).toBe('enc');
  });

  it('publicJwk uses P-256 curve', async () => {
    const { publicJwk } = await generateEphemeralKeyPair();
    expect(publicJwk.kty).toBe('EC');
    expect(publicJwk.crv).toBe('P-256');
  });

  it('publicJwk does not contain private key material', async () => {
    const { publicJwk } = await generateEphemeralKeyPair();
    expect(publicJwk).not.toHaveProperty('d');
  });

  it('publicJwk contains the required EC public key coordinates', async () => {
    const { publicJwk } = await generateEphemeralKeyPair();
    expect(publicJwk).toHaveProperty('x');
    expect(publicJwk).toHaveProperty('y');
  });

  it('publicJwk has a kid derived from the JWK Thumbprint', async () => {
    const { publicJwk } = await generateEphemeralKeyPair();
    expect(typeof publicJwk.kid).toBe('string');
    expect(publicJwk.kid!.length).toBeGreaterThan(0);
  });

  it('privateKey is a KeyObject (Node.js native key)', async () => {
    const { privateKey } = await generateEphemeralKeyPair();
    expect(privateKey).toBeInstanceOf(KeyObject);
  });

  it('privateKey can be used directly with compactDecrypt', async () => {
    const { privateKey, publicJwk } = await generateEphemeralKeyPair();

    const recipientPublicKey = await importJWK(publicJwk, 'ECDH-ES');
    const plaintext = new TextEncoder().encode('hello');
    const jwe = await new CompactEncrypt(plaintext)
      .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
      .encrypt(recipientPublicKey);

    // Decrypt must succeed with the corresponding private key, no PEM conversion needed.
    const { plaintext: decrypted } = await compactDecrypt(jwe, privateKey);
    expect(new TextDecoder().decode(decrypted)).toBe('hello');
  });

  it('each call generates a distinct key pair', async () => {
    const first = await generateEphemeralKeyPair();
    const second = await generateEphemeralKeyPair();

    expect(first.publicJwk.x).not.toBe(second.publicJwk.x);
    expect(first.publicJwk.y).not.toBe(second.publicJwk.y);
  });
});
