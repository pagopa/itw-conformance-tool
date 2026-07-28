import { type ECKey, type ECPrivateKey, type JwkPrivateKey, type JwkPublicKey } from './z-jwk.js';

import type { TrustAnchorFederationJwk } from '@itw-conformance-tool/crypto';
import type { SignCallback } from '@pagopa/io-wallet-oid-federation';
import type { JsonWebKey } from 'node:crypto';

export interface JwksRepository {
  readonly getEncrypt: () => JwkKeyPair<'EC'>;
  readonly getSign: () => JwkKeyPair<'EC'>;
  /** Returns the Trust Anchor's federation private key. Trust Marks are issued by the
   * Trust Anchor, so the issuer signs the Trust Mark embedded in its own Entity
   * Configuration with this key rather than with `getSign()`. */
  readonly getTrustAnchorFederation: () => TrustAnchorFederationJwk;
  /** Returns the persisted issuer certificate chain (leaf first, followed by
   * the issuing intermediate CA certificate) as PEM-encoded strings. The
   * leaf's public key always corresponds to the private key returned by
   * `getSign()`. */
  readonly issuerCertificateChain: () => readonly string[];
}

interface JwkKeyPair<A> {
  readonly private: { readonly kty: A } & JwkPrivateKey & Required<Pick<ECPrivateKey, 'kid'>>;
  readonly public: { readonly kty: A } & JwkPublicKey & Required<Pick<ECKey, 'kid'>>;
}

/**
 * Signs the given payload using the provided JWK and returns the raw signature bytes.
 *
 * @param toBeSigned - The signing input bytes ("header_b64url.payload_b64url")
 * @param jwk - The JSON Web Key to use for signing
 * @returns A Uint8Array containing the raw signature bytes
 */
export const signCallback: SignCallback = async ({ jwk, toBeSigned }) => {
  const alg = jwk.alg ?? 'ES256';
  const key = await crypto.subtle.importKey(
    'jwk',
    jwk as JsonWebKey,
    { name: 'ECDSA', namedCurve: alg === 'ES256' ? 'P-256' : alg === 'ES384' ? 'P-384' : 'P-521' },
    true, // Rende la chiave estraibile (opzionale, ma consigliato)
    ['sign'] // Specifica lo scopo della chiave privata
  );

  // crypto.subtle.sign requires the hash algorithm to be specified explicitly as a
  // Web Crypto API name ("SHA-256", "SHA-384", "SHA-512"), whereas JWA algorithm names
  // (e.g. "ES256") encode both the curve and the hash in a single string.
  // importJWK already selects the correct curve from the JWK, but crypto.subtle
  // does not derive the hash automatically — it must be passed separately.
  // ES256 → SHA-256, ES384 → SHA-384, ES512 → SHA-512 (per RFC 7518 §3.4).
  const hashAlgorithm = alg === 'ES384' ? 'SHA-384' : alg === 'ES512' ? 'SHA-512' : 'SHA-256';
  const signatureBuffer = await crypto.subtle.sign(
    { hash: hashAlgorithm, name: 'ECDSA' },
    key,
    Buffer.from(toBeSigned)
  );

  return new Uint8Array(signatureBuffer);
};
