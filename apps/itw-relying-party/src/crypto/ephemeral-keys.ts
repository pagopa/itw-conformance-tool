import { calculateJwkThumbprint, exportJWK, generateKeyPair } from 'jose';

import type { JWK, KeyLike } from 'jose';

export interface EphemeralKeyPair {
  privateKey: KeyLike;
  publicJwk: JWK;
}

/** Generates an ephemeral ECDH-ES key pair on the P-256 curve
 *
 * @returns An object containing the private key and the public key in JWK format,
 * with `alg` set to `ECDH-ES`, `use` set to `enc`, and `kid` set to the
 * SHA-256 JWK Thumbprint (RFC 7638) of the public key.
 */
export async function generateEphemeralKeyPair(): Promise<EphemeralKeyPair> {
  const { privateKey, publicKey } = await generateKeyPair('ECDH-ES', { crv: 'P-256' });

  const rawPublicJwk = await exportJWK(publicKey);
  const kid = await calculateJwkThumbprint(rawPublicJwk, 'sha256');

  const publicJwk: JWK = {
    ...rawPublicJwk,
    alg: 'ECDH-ES',
    kid,
    use: 'enc'
  };

  return { privateKey, publicJwk };
}
