import { calculateJwkThumbprint, type JWK } from 'jose';

import type { JwkKey } from '../plugins/keys.js';
import type { JsonWebKey } from '@pagopa/io-wallet-oid-federation';

/**
 * Derivations from a stored private JWK to the public key a federation statement
 * publishes.
 *
 * They live outside `statements.ts` because two callers need them for different
 * keys: the `keys` plugin derives each subordinate's published key once at
 * startup, and `statements.ts` derives the Trust Anchor's own key per statement
 * — the latter cannot be precomputed, since a fault substitutes a different key
 * for it.
 */

/** Asserts the two members a published key needs to be resolvable.
 *
 * `kid` is not decoration: `createItWalletEntityConfiguration` resolves the key
 * that signed a statement out of the statement's own `jwks` by `header.kid`, so
 * a key without one cannot be pointed at.
 */
export function assertPublishableJwk(jwk: { kid?: unknown; kty?: unknown }): void {
  if (typeof jwk.kty !== 'string' || jwk.kty.length === 0) {
    throw new Error('Federation JWK is missing a valid "kty"');
  }
  if (typeof jwk.kid !== 'string' || jwk.kid.length === 0) {
    throw new Error('Federation JWK is missing a valid "kid"');
  }
}

/** Strips private key material from a stored federation JWK, preserving every other
 * member (including `kid`) unchanged.
 *
 * This matches the issuer's own derivation (packages/issuer/src/crypto.ts `toPublicJwk`)
 * and is also correct for the Trust Anchor's own key: neither the issuer nor the Trust
 * Anchor ever recompute their `kid`, so the stored `kid` is exactly what each entity
 * advertises in its own entity configuration.
 */
export function stripPrivateParams(jwk: JwkKey): JsonWebKey {
  const { d, key_ops, ...publicJwk } = jwk;
  void d;
  void key_ops;

  assertPublishableJwk(publicJwk);

  return publicJwk as JsonWebKey;
}

/** Derives a leaf's public federation JWK as the corresponding service advertises it:
 * the stored `kid` is discarded and replaced with an RFC 7638 JWK thumbprint computed
 * over the key.
 *
 * RFC 7638 thumbprints only cover a key's canonical required members (e.g. `kty`, `crv`,
 * `x`, `y` for EC) and ignore other stored members, including `d` and the original `kid`.
 * The subordinate statement must use the same identifier as the leaf Entity Configuration
 * so verifiers can resolve the leaf signing key through the trust chain.
 */
export async function toThumbprintPublicJwk(jwk: JwkKey): Promise<JsonWebKey> {
  const { d, key_ops, kid: _storedKid, ...publicJwk } = jwk;
  void d;
  void key_ops;
  void _storedKid;

  if (typeof publicJwk.kty !== 'string' || publicJwk.kty.length === 0) {
    throw new Error('Federation JWK is missing a valid "kty"');
  }

  const kid = await calculateJwkThumbprint(jwk as unknown as JWK);

  return { ...publicJwk, kid } as JsonWebKey;
}

/** Publishes a key with the certificate chain that certifies it, or unchanged when
 * there is none.
 *
 * An absent chain is not the same as an empty one: a key published with `x5c: []`
 * claims a certificate binding and then supplies nothing to check it against, so
 * the member is omitted entirely instead.
 */
export function withCertificateChain(publicJwk: JsonWebKey, certificateChain?: string[]): JsonWebKey {
  if (!certificateChain || certificateChain.length === 0) {
    return publicJwk;
  }

  return { ...publicJwk, x5c: certificateChain } as JsonWebKey;
}
