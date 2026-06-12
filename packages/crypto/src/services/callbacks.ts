import { createPrivateKey, createPublicKey } from 'node:crypto';

import { CompactEncrypt, compactDecrypt, exportJWK, importJWK, importPKCS8, jwtVerify, SignJWT } from 'jose';

import type {
  DecryptJweCallback,
  EncryptJweCallback,
  Jwk,
  SignJwtCallback,
  VerifyJwtCallback
} from '../types/types.js';

/** Exports the public JWK from a PEM-encoded private key, without private fields.
 *
 * @param pem - The PEM-encoded private key
 * @returns The public JWK
 */
async function publicJwkFromPrivatePem(pem: string): Promise<Jwk> {
  const nodePublicKey = createPublicKey(createPrivateKey(pem));
  const jwk = await exportJWK(nodePublicKey);
  return jwk as Jwk;
}

/**
 * Creates a SignJwtCallback using:
 * - `authRequestPrivateKeyPem` for `method: 'jwk'` (authorization request signing)
 * - `signingPrivateKeyPem` for all other methods (x5c, federation, custom)
 *
 * @param authRequestPrivateKeyPem - PEM-encoded private key for JWK method
 * @param signingPrivateKeyPem - PEM-encoded private key for other methods
 * @returns A SignJwtCallback function
 */
export function createSignJwtCallback(authRequestPrivateKeyPem: string, signingPrivateKeyPem: string): SignJwtCallback {
  return async (jwtSigner, jwt) => {
    const isJwkMethod = jwtSigner.method === 'jwk';
    const pem = isJwkMethod ? authRequestPrivateKeyPem : signingPrivateKeyPem;

    const privateKey = await importPKCS8(pem, jwtSigner.alg);
    const signerJwk: Jwk = isJwkMethod ? jwtSigner.publicJwk : await publicJwkFromPrivatePem(pem);

    const token = await new SignJWT(jwt.payload)
      .setProtectedHeader({ ...jwt.header, alg: jwtSigner.alg })
      .sign(privateKey);

    return { jwt: token, signerJwk };
  };
}

/**
 * Creates a VerifyJwtCallback. Only `method: 'jwk'` is verified locally using
 * the embedded public JWK. All other methods (x5c, federation, custom) require
 * external trust chain resolution and return `{ verified: false }`.
 *
 * @returns A VerifyJwtCallback function
 */
export function createVerifyJwtCallback(): VerifyJwtCallback {
  return async (jwtSigner, jwt) => {
    if (jwtSigner.method !== 'jwk') {
      return { verified: false };
    }

    try {
      const publicKey = await importJWK(jwtSigner.publicJwk, jwtSigner.alg);
      await jwtVerify(jwt.compact, publicKey, { algorithms: [jwtSigner.alg] });
      return { verified: true, signerJwk: jwtSigner.publicJwk };
    } catch {
      return { verified: false, signerJwk: jwtSigner.publicJwk };
    }
  };
}

/**
 * Creates a DecryptJweCallback that decrypts JWEs using the ECDH-ES private
 * key PEM (typically the authorization-response decryption key).
 *
 * @param authResponsePrivateKeyPem - PEM-encoded private key for decryption
 * @returns A DecryptJweCallback function
 */
export function createDecryptJweCallback(authResponsePrivateKeyPem: string): DecryptJweCallback {
  return async (jwe) => {
    try {
      const privateKey = await importPKCS8(authResponsePrivateKeyPem, 'ECDH-ES');
      const { plaintext } = await compactDecrypt(jwe, privateKey);
      const decryptionJwk = await publicJwkFromPrivatePem(authResponsePrivateKeyPem);
      return {
        decrypted: true,
        decryptionJwk,
        payload: new TextDecoder().decode(plaintext)
      };
    } catch {
      return { decrypted: false };
    }
  };
}

/**
 * Creates an EncryptJweCallback that encrypts data for the recipient identified
 * by the public JWK embedded in `jweEncryptor`.
 *
 * @returns An EncryptJweCallback function
 */
export function createEncryptJweCallback(): EncryptJweCallback {
  return async (jweEncryptor, data) => {
    const { publicJwk, alg, enc } = jweEncryptor;

    const recipientPublicKey = await importJWK(publicJwk, alg);

    const protectedHeader: Record<string, unknown> = { alg, enc };
    if (jweEncryptor.apu) protectedHeader['apu'] = jweEncryptor.apu;
    if (jweEncryptor.apv) protectedHeader['apv'] = jweEncryptor.apv;

    const jweCompact = await new CompactEncrypt(new TextEncoder().encode(data))
      .setProtectedHeader(protectedHeader as Parameters<CompactEncrypt['setProtectedHeader']>[0])
      .encrypt(recipientPublicKey);

    return { encryptionJwk: publicJwk, jwe: jweCompact };
  };
}
