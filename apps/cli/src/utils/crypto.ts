import { generateKeyPairSync } from 'node:crypto';

function createEcPrivateJwk(descriptor: {
  alg: 'ES256' | 'ECDH-ES';
  keyOps: string[];
  kid: string;
  use: 'sig' | 'enc';
}) {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const privateJwk = privateKey.export({ format: 'jwk' });

  return {
    ...privateJwk,
    kid: descriptor.kid,
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
    kid: 'issuer-signing-key',
    use: 'sig',
    alg: 'ES256',
    keyOps: ['sign']
  });

  const encryption = createEcPrivateJwk({
    kid: 'issuer-encryption-key',
    use: 'enc',
    alg: 'ECDH-ES',
    keyOps: ['deriveBits']
  });

  return { keys: [signing, encryption] };
}

export function createRelyingPartyPrivateKeys() {
  const signing = createEcPrivateJwk({
    kid: 'rp-signing-key',
    use: 'sig',
    alg: 'ES256',
    keyOps: ['sign']
  });

  const encryption = createEcPrivateJwk({
    kid: 'rp-encryption-key',
    use: 'enc',
    alg: 'ECDH-ES',
    keyOps: ['deriveBits']
  });

  const federation = createEcPrivateJwk({
    kid: 'rp-federation-key',
    use: 'sig',
    alg: 'ES256',
    keyOps: ['sign']
  });

  return { keys: [signing, encryption, federation] };
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
    kid: 'issuer-intermediate-key',
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
    kid: 'trust-anchor-federation-key',
    use: 'sig',
    alg: 'ES256',
    keyOps: ['sign']
  });
}
