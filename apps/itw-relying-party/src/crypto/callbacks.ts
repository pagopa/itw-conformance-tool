import { createHash, createPublicKey, createPrivateKey, randomBytes } from 'node:crypto';

import { CompactEncrypt, compactDecrypt, exportJWK, importJWK, importPKCS8, jwtVerify, SignJWT } from 'jose';

import type {
  DecryptJweCallback,
  EncryptJweCallback,
  GenerateRandomCallback,
  HashAlgorithm,
  Jwk,
  SignJwtCallback,
  VerifyJwtCallback
} from '@pagopa/io-wallet-oauth2';

const HASH_ALG_MAP: Record<string, string> = {
  'sha-256': 'sha256',
  'sha-384': 'sha384',
  'sha-512': 'sha512'
};

export const hashCallback = (data: Uint8Array, alg: HashAlgorithm): Uint8Array => {
  const nodeAlg = HASH_ALG_MAP[alg];
  if (!nodeAlg) throw new Error(`Unsupported hash algorithm: ${alg}`);
  return new Uint8Array(createHash(nodeAlg).update(data).digest());
};

export const generateRandomCallback: GenerateRandomCallback = (byteLength): Uint8Array =>
  new Uint8Array(randomBytes(byteLength));

/** Exports the public JWK from a PEM-encoded private key, without private fields. */
async function publicJwkFromPrivatePem(pem: string): Promise<Jwk> {
  const nodePublicKey = createPublicKey(createPrivateKey(pem));
  const jwk = await exportJWK(nodePublicKey);
  return jwk as Jwk;
}

/**
 * Creates a SignJwtCallback using:
 * - `authRequestPrivateKeyPem` for `method: 'jwk'` (authorization request signing)
 * - `signingPrivateKeyPem` for all other methods (x5c, federation, custom)
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
