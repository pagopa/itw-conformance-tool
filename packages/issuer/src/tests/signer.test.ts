import { compactVerify, exportJWK, generateKeyPair, importJWK } from 'jose';
import { describe, expect, it } from 'vitest';

import { signJwtCallback } from '../signer.js';

describe('signJwtCallback', () => {
  it('produces a signature verifiable with the corresponding public key', async () => {
    const { privateKey, publicKey } = await generateKeyPair('ES256');
    const privateJwk = await exportJWK(privateKey);
    const publicJwk = await exportJWK(publicKey);
    const privateJwkForSigner = {
      ...privateJwk,
      kid: privateJwk.kid ?? 'test-kid',
      kty: privateJwk.kty ?? 'EC'
    };

    const payload = new TextEncoder().encode('issuer-signature-test-payload');
    const signature = await signJwtCallback({
      jwk: privateJwkForSigner,
      toBeSigned: payload
    });

    const protectedHeader = Buffer.from(JSON.stringify({ alg: 'ES256' })).toString('base64url');
    const payloadEncoded = Buffer.from(payload).toString('base64url');
    const signatureEncoded = Buffer.from(signature).toString('base64url');
    const compactJws = `${protectedHeader}.${payloadEncoded}.${signatureEncoded}`;

    const josePublicKey = await importJWK(publicJwk, 'ES256');
    const verified = await compactVerify(compactJws, josePublicKey);

    expect(Buffer.from(verified.payload).equals(Buffer.from(payload))).toBe(true);
  });

  it('throws when jwk cannot be imported', async () => {
    const payload = new TextEncoder().encode('payload');

    await expect(
      signJwtCallback({
        jwk: { kid: 'invalid-kid', kty: 'EC' },
        toBeSigned: payload
      })
    ).rejects.toThrow();
  });
});
