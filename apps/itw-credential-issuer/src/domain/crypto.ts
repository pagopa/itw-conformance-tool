import {
  getCertificateChainPublicKey,
  generateRandomBytes,
  hashCallback,
  type HashAlgorithm
} from '@itw-conformance-tool/crypto';
import {
  type CallbackContext,
  type DecryptJweCallback,
  type EncryptJweCallback,
  type Jwk,
  type JweEncryptor,
  type JwtSigner,
  type SignJwtCallback,
  type VerifyJwtCallback,
  clientAuthenticationAnonymous
} from '@pagopa/io-wallet-oauth2';
import { decodeBase64, encodeToUtf8String } from '@pagopa/io-wallet-utils';
import { CompactEncrypt, type JWK, SignJWT, compactDecrypt, decodeJwt, importJWK, jwtVerify } from 'jose';

import type { ItWalletEntityConfigurationClaims } from '@pagopa/io-wallet-oid-federation';

export const callbacks = {
  clientAuthentication: clientAuthenticationAnonymous(),

  generateRandom: async (bytes: number) => generateRandomBytes(bytes),

  hash: async (data: Uint8Array, alg: string) => hashCallback(data, alg as HashAlgorithm),

  verifyJwt: async (
    signer: Parameters<NonNullable<CallbackContext['verifyJwt']>>[0],
    { compact }: Parameters<NonNullable<CallbackContext['verifyJwt']>>[1]
  ) => {
    let jwk: JWK;

    if (signer.method === 'did') {
      jwk = JSON.parse(encodeToUtf8String(decodeBase64(signer.didUrl.split('#')[0].replace('did:jwk:', '')))) as JWK;
    } else if (signer.method === 'jwk') {
      jwk = signer.publicJwk as JWK;
    } else if (signer.method === 'x5c') {
      jwk = await getCertificateChainPublicKey({ alg: signer.alg, certificateChain: signer.x5c });
    } else if (signer.method === 'federation') {
      if (signer.trustChain && signer.trustChain.length > 0) {
        jwk = trustChainToJwk(signer.trustChain, signer.kid) as JWK;
      } else {
        throw new Error('Trust chain not found');
      }
    } else {
      throw new Error('Verifier method not supported');
    }

    const publicKey = await importJWK(jwk);

    try {
      await jwtVerify(compact, publicKey, { clockTolerance: 300 });
      return { signerJwk: jwk as Jwk, verified: true as const };
    } catch {
      return { verified: false as const };
    }
  }
};

export const getSignJwtCallback =
  (privateJwks: Jwk[]): SignJwtCallback =>
  async (signer, { header, payload }) => {
    let jwk: Jwk;

    if (signer.method === 'did') {
      jwk = JSON.parse(encodeToUtf8String(decodeBase64(signer.didUrl.split('#')[0].replace('did:jwk:', '')))) as Jwk;
    } else if (signer.method === 'jwk') {
      jwk = signer.publicJwk;
    } else if (signer.method === 'x5c') {
      jwk = {
        ...(await getCertificateChainPublicKey({ alg: signer.alg, certificateChain: signer.x5c })),
        kid: signer.kid
      } as Jwk;
    } else if (signer.method === 'federation') {
      if (signer.trustChain && signer.trustChain.length > 0) {
        jwk = trustChainToJwk(signer.trustChain, signer.kid);
      } else {
        throw new Error('Trust chain not found');
      }
    } else {
      throw new Error('Signer method not supported');
    }

    const privateJwk = privateJwks.find((jwkPrv) => jwkPrv.kid === jwk.kid);

    if (!privateJwk) {
      throw new Error(`No private key available for public jwk \n${JSON.stringify(jwk, null, 2)}`);
    }

    const josePrivateKey = await importJWK(privateJwk, signer.alg);
    const jwt = await new SignJWT(payload as Record<string, unknown>)
      .setProtectedHeader({ ...header, alg: signer.alg })
      .sign(josePrivateKey);

    return { jwt, signerJwk: jwk };
  };

export const trustChainToJwk = (trustChains: string[], signerKid: string): Jwk =>
  retrieveJwkFromEntityConf(trustChains[0] as string, signerKid);

const retrieveJwkFromEntityConf = (entityStatementJwt: string, signerKid: string): Jwk => {
  const decodedEntityConfig = decodeJwt<ItWalletEntityConfigurationClaims>(entityStatementJwt);

  const jwks: Jwk[] = [];
  const topLevelJwks = (decodedEntityConfig as { jwks?: { keys?: Jwk[] } }).jwks?.keys;
  if (Array.isArray(topLevelJwks)) {
    jwks.push(...topLevelJwks);
  }

  if (decodedEntityConfig.metadata) {
    for (const entry of Object.values(decodedEntityConfig.metadata)) {
      if (
        (entry as { jwks?: { keys?: Jwk[] } }).jwks &&
        Array.isArray((entry as { jwks: { keys: Jwk[] } }).jwks.keys)
      ) {
        jwks.push(...(entry as { jwks: { keys: Jwk[] } }).jwks.keys);
      }
    }
  }

  const federationJwk = jwks.find((key) => key.kid === signerKid);
  if (!federationJwk) {
    throw new Error('Key not found in trust chain');
  }

  return {
    ...federationJwk,
    ...(federationJwk.x5c ? { x5c: Array.isArray(federationJwk.x5c) ? federationJwk.x5c : [federationJwk.x5c] } : {})
  } as Jwk;
};

export const getEncryptJweCallback =
  (publicKey: Jwk): EncryptJweCallback =>
  async (_: JweEncryptor, data: string) => {
    const josePublicKey = await importJWK(publicKey, 'ECDH-ES');

    const jwe = await new CompactEncrypt(new TextEncoder().encode(data))
      .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A128CBC-HS256', kid: publicKey.kid, typ: 'oauth-authz-req+jwt' })
      .encrypt(josePublicKey);

    return { encryptionJwk: publicKey, jwe };
  };

export const getDecryptJweCallback =
  (privateKey: Jwk): DecryptJweCallback =>
  async (jwe: string) => {
    try {
      const josePrivateKey = await importJWK(privateKey, 'ECDH-ES');
      const decrypted = await compactDecrypt(jwe, josePrivateKey);
      return {
        decrypted: true as const,
        decryptionJwk: privateKey,
        payload: new TextDecoder().decode(decrypted.plaintext)
      };
    } catch {
      return { decrypted: false as const };
    }
  };

export const getVerifyJwtCallback =
  (publicKey: Jwk): VerifyJwtCallback =>
  async (_: JwtSigner, jwt) => {
    try {
      const josePublicKey = await importJWK(publicKey, 'ES256');
      await jwtVerify(jwt.compact, josePublicKey, { clockTolerance: 300 });
      return { signerJwk: publicKey, verified: true as const };
    } catch {
      return { verified: false as const };
    }
  };

export function toPublicJwk<T extends JWK>(jwk: T): Omit<T, 'd' | 'key_ops'>;
export function toPublicJwk<T extends JWK>(jwk: T[]): Omit<T, 'd' | 'key_ops'>[];
export function toPublicJwk<T extends JWK>(jwk: T | T[]): Omit<T, 'd' | 'key_ops'> | Omit<T, 'd' | 'key_ops'>[] {
  if (Array.isArray(jwk)) {
    return jwk.map((key) => {
      const { d, key_ops, ...pub } = key;
      void d;
      void key_ops;
      return pub;
    });
  }
  const { d, key_ops, ...pub } = jwk;
  void d;
  void key_ops;
  return pub;
}

export async function getIssuerPublicKey(header: Record<string, unknown>, kid: string): Promise<JWK> {
  if (header.trust_chain && Array.isArray(header.trust_chain)) {
    return trustChainToJwk(header.trust_chain as string[], kid) as JWK;
  }

  if (header.x5c && Array.isArray(header.x5c)) {
    return await getCertificateChainPublicKey({ alg: 'ES256', certificateChain: header.x5c as string[] });
  }

  throw new Error("header must contain either 'trust_chain' or 'x5c' for issuer verification");
}
