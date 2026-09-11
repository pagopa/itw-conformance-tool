import { createHash, generateKeyPairSync } from 'node:crypto';

function createEcPrivateJwk(descriptor: { alg: 'ES256' | 'ECDH-ES'; keyOps: string[]; use: 'sig' | 'enc' }) {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const privateJwk = privateKey.export({ format: 'jwk' });
  const thumbprintPayload = JSON.stringify({
    crv: privateJwk.crv,
    kty: privateJwk.kty,
    x: privateJwk.x,
    y: privateJwk.y
  });

  return {
    ...privateJwk,
    kid: createHash('sha256').update(thumbprintPayload).digest('base64url'),
    alg: descriptor.alg,
    use: descriptor.use,
    key_ops: descriptor.keyOps
  };
}

/** Generates and returns a JWKS containing issuer runtime-compatible EC keys.
 *
 * The issuer runtime requires:
 * - one ES256 signing key (use=sig)
 * - one ECDH-ES encryption key (use=enc)
 *
 * @returns A JSON string representing the issuer JWKS.
 */
export function createIssuerPrivateKeys() {
  const signing = createEcPrivateJwk({
    use: 'sig',
    alg: 'ES256',
    keyOps: ['sign']
  });

  const encryption = createEcPrivateJwk({
    use: 'enc',
    alg: 'ECDH-ES',
    keyOps: ['deriveBits']
  });

  return { keys: [signing, encryption] };
}

/** Generates the Relying Party's application JWKS: the ES256 key that signs
 * Request Objects and the ECDH-ES key that encrypts them and decrypts the
 * Authorization Response.
 *
 * The federation key is deliberately absent — it lives in its own
 * `rp/federation-key.jwk.json` (see `createRelyingPartyFederationKey`). Both
 * roles used to share this file as two `use=sig` entries told apart only by
 * their position in the array, which meant reordering them silently swapped the
 * key that signs a Request Object with the key that signs the Entity
 * Configuration. Separate files make the roles impossible to confuse.
 *
 * @returns A JWKS containing the Relying Party application keys.
 */
export function createRelyingPartyPrivateKeys() {
  const signing = createEcPrivateJwk({
    use: 'sig',
    alg: 'ES256',
    keyOps: ['sign']
  });

  const encryption = createEcPrivateJwk({
    use: 'enc',
    alg: 'ECDH-ES',
    keyOps: ['deriveBits']
  });

  return { keys: [signing, encryption] };
}

/** Generates the Relying Party's OpenID Federation signing key.
 *
 * It signs the Relying Party Entity Configuration and its Trust Mark, and
 * nothing else: Request Objects are signed with the application key from
 * `createRelyingPartyPrivateKeys`. Mirrors `createTrustAnchorFederationKey`,
 * which keeps the Trust Anchor's federation key in a single-JWK file too.
 *
 * @returns The Relying Party federation private JWK.
 */
export function createRelyingPartyFederationKey() {
  return createEcPrivateJwk({
    use: 'sig',
    alg: 'ES256',
    keyOps: ['sign']
  });
}

/** Generates and returns an EC P-256 private ES256 signing key for the
 * Relying Party intermediate CA.
 *
 * The intermediate CA's private key signs `rp/federation-cert.pem` and its
 * public key is embedded in `rp/intermediate-cert.pem`, which the Trust Anchor
 * federation key signs in turn.
 *
 * @returns The Relying Party intermediate CA private JWK.
 */
export function createRelyingPartyIntermediateKey() {
  return createEcPrivateJwk({
    use: 'sig',
    alg: 'ES256',
    keyOps: ['sign']
  });
}

/** Generates a JWKS containing the Wallet Provider attestation signing key. */
export function createWalletProviderPrivateKeys() {
  return {
    keys: [
      createEcPrivateJwk({
        use: 'sig',
        alg: 'ES256',
        keyOps: ['sign']
      })
    ]
  };
}

/** Generates and returns a JWKS containing a single EC P-256 private
 * ES256 signing key for the issuer intermediate CA.
 *
 * The intermediate CA's private key signs `issuer/cert.pem` and its
 * public key is embedded in `issuer/intermediate-cert.pem`.
 *
 * @returns A JSON string representing the intermediate CA JWKS.
 */
export function createIssuerIntermediateKey() {
  return createEcPrivateJwk({
    use: 'sig',
    alg: 'ES256',
    keyOps: ['sign']
  });
}

/** Generates and returns an EC P-256 private ES256 signing key for the
 * Wallet Provider intermediate CA.
 *
 * The intermediate CA's private key signs `wallet-provider/cert.pem` and its
 * public key is embedded in `wallet-provider/intermediate-cert.pem`.
 *
 * @returns A JSON string representing the Wallet Provider intermediate CA JWK.
 */
export function createWalletProviderIntermediateKey() {
  return createEcPrivateJwk({
    use: 'sig',
    alg: 'ES256',
    keyOps: ['sign']
  });
}

/** Generates and returns an EC P-256 private key JWK for trust-anchor
 * federation entity- and subordinate-statement signing.
 */
export function createTrustAnchorFederationKey() {
  return createEcPrivateJwk({
    use: 'sig',
    alg: 'ES256',
    keyOps: ['sign']
  });
}
