import * as crypto from 'node:crypto';

import {
  type CallbackContext,
  type DecryptJweCallback,
  type EncryptJweCallback,
  type JweEncryptor,
  type Jwk,
  type SignJwtCallback,
  clientAuthenticationAnonymous
} from '@pagopa/io-wallet-oauth2';
import { decodeBase64, encodeToUtf8String } from '@pagopa/io-wallet-utils';
import { FlattenedEncrypt, type JWK, SignJWT, compactDecrypt, decodeJwt, importJWK, jwtVerify } from 'jose';

import { getCertificateChainPublicKey } from './x509.js';

import type { ItWalletEntityConfigurationClaims } from '@pagopa/io-wallet-oid-federation';

export const callbacks = {
  /**
   * Provides client authentication callback (currently returns "none").
   */
  // @ts-expect-error - The type definition for clientAuthentication allows for more
  // specific types, but here we return a generic anonymous authentication
  // method.
  clientAuthentication: clientAuthenticationAnonymous(),

  /**
   * Generates a cryptographically secure random byte buffer.
   *
   * @param bytes - The number of bytes to generate
   * @returns A Buffer containing random bytes
   */
  generateRandom: async (bytes) => new Uint8Array(crypto.randomBytes(bytes)),

  /**
   * Hashes data using the specified algorithm.
   *
   * @param data - The data to hash
   * @param alg - The hashing algorithm to use
   * @returns A Buffer containing the hash
   */
  hash: async (data, alg) =>
    new Uint8Array(crypto.createHash(alg.replace('-', '').toLowerCase()).update(data).digest()),

  /**
   * Verifies a JWT using the signer's public JWK.
   *
   * @param signer - The signer containing method and key information
   * @param compact - The compact serialized JWT
   * @param payload - The JWT payload used for date validation
   * @returns An object indicating verification result and optionally the signer's JWK
   */
  verifyJwt: async (signer, { compact, payload }) => {
    let jwk: JWK;

    if (signer.method === 'did') {
      jwk = JSON.parse(encodeToUtf8String(decodeBase64(signer.didUrl.split('#')[0].replace('did:jwk:', ''))));
    } else if (signer.method === 'jwk') {
      jwk = signer.publicJwk;
    } else if (signer.method === 'x5c') {
      jwk = await getCertificateChainPublicKey({
        alg: signer.alg,
        certificateChain: signer.x5c
      });
    } else if (signer.method === 'federation') {
      if (signer.trustChain && signer.trustChain.length > 0) {
        jwk = trustChainToJwk(signer.trustChain, signer.kid);
      } else {
        throw new Error('Trust chain not found');
      }
    } else {
      if (payload.iss) {
        const result = await fetch(`${payload.iss}/.well-known/openid-federation`);
        const resultBody = await result.text();
        jwk = retrieveJwkToEntityConf(resultBody, signer.kid);
      } else {
        throw new Error('Verifier method not supported');
      }
    }

    const publicKey = await importJWK(jwk, signer.alg);

    try {
      await jwtVerify(compact, publicKey, {
        clockTolerance: 300 // 5 minutes clock tolerance
      });
      return {
        signerJwk: jwk as Jwk,
        verified: true
      };
    } catch {
      return {
        verified: false
      };
    }
  }
} as const satisfies Partial<CallbackContext>;

/**
 * Returns a callback function for signing JWTs using the matching private key.
 *
 * @param privateJwks - Array of private JWKs to choose from for signing
 * @returns A SignJwtCallback function
 */
export const getSignJwtCallback =
  (privateJwks: Jwk[]): SignJwtCallback =>
  async (signer, { header, payload }) => {
    let jwk = {} as Jwk;
    if (signer.method === 'did') {
      jwk = JSON.parse(encodeToUtf8String(decodeBase64(signer.didUrl.split('#')[0].replace('did:jwk:', ''))));
    } else if (signer.method === 'jwk') {
      jwk = signer.publicJwk;
    } else if (signer.method === 'x5c') {
      jwk = {
        ...(await getCertificateChainPublicKey({
          alg: signer.alg,
          certificateChain: signer.x5c
        })),
        kid: signer.kid
      } as Jwk;
    } else if (signer.method === 'federation') {
      if (signer.trustChain && signer.trustChain.length > 0) {
        jwk = trustChainToJwk(signer.trustChain, signer.kid);
      }
    } else {
      throw new Error('Signer method not supported');
    }

    const privateJwk = privateJwks.find((jwkPrv) => jwkPrv.kid === jwk.kid);

    if (!privateJwk) {
      throw new Error(`No private key available for public jwk \n${JSON.stringify(jwk, null, 2)}`);
    }

    const josePrivateKey = await importJWK(privateJwk, signer.alg);
    const jwt = await new SignJWT(payload).setProtectedHeader({ ...header, alg: signer.alg }).sign(josePrivateKey);

    return {
      jwt: jwt,
      signerJwk: jwk
    };
  };

export function trustChainToJwk(trustChains: string[], signerKid: string): Jwk {
  return retrieveJwkToEntityConf(trustChains[0], signerKid);
}

function retrieveJwkToEntityConf(entityStatementJwt: string, signerKid: string | undefined): Jwk {
  const decodedEntityConfig = decodeJwt<ItWalletEntityConfigurationClaims>(entityStatementJwt);

  const jwks: Jwk[] = [];
  if (decodedEntityConfig.metadata) {
    for (const entry of Object.values(decodedEntityConfig.metadata)) {
      if (entry.jwks && Array.isArray(entry.jwks.keys)) {
        jwks.push(...entry.jwks.keys);
      }
    }
  }

  const federationJwk = jwks.find((key) => key.kid === signerKid);
  if (!federationJwk) {
    throw new Error('Key not found in trust chain');
  }

  // Convert x5c to array if it's a string, need to adapt to jose
  const transformedJwk = {
    ...federationJwk,
    ...(federationJwk.x5c
      ? {
          x5c: federationJwk.x5c
            ? Array.isArray(federationJwk.x5c)
              ? federationJwk.x5c
              : [federationJwk.x5c]
            : undefined
        }
      : {})
  };
  return transformedJwk as Jwk;
}

/**
 * Returns a callback function for signing JWTs using the matching private key.
 *
 * @param privateJwks - Array of private JWKs to choose from for signing
 * @returns A SignJwtCallback function
 */
export const getEncryptJweCallback =
  (publicKey: Jwk): EncryptJweCallback =>
  async (_: JweEncryptor, data: string) => {
    const josePublicKey = await importJWK(publicKey, 'ES256');

    const jwe = await new FlattenedEncrypt(new TextEncoder().encode(data))
      .setProtectedHeader({
        alg: 'ES256',
        kid: publicKey.kid,
        typ: 'oauth-authz-req+jwt'
      })
      .encrypt(josePublicKey);

    return {
      encryptionJwk: publicKey,
      jwe: jwe.ciphertext
    };
  };

/**
 * Returns a callback function for signing JWTs using the matching private key.
 *
 * @param privateJwks - Array of private JWKs to choose from for signing
 * @returns A SignJwtCallback function
 */
export const getDecryptJweCallback =
  (privateKey: Jwk): DecryptJweCallback =>
  async (jwe: string) => {
    try {
      const josePrivateKey = await importJWK(privateKey, 'ECDH-ES');
      const decrypted = await compactDecrypt(jwe, josePrivateKey);

      return {
        decrypted: true,
        decryptionJwk: privateKey,
        payload: new TextDecoder().decode(decrypted.plaintext)
      };
    } catch {
      return {
        decrypted: false
      };
    }
  };
