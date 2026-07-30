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

  const federation = createEcPrivateJwk({
    use: 'sig',
    alg: 'ES256',
    keyOps: ['sign']
  });

  return { keys: [signing, encryption, federation] };
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
