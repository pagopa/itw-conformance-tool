import { generateEcPrivateJwk } from '@itw-conformance-tool/crypto';

/** Generates and returns a JWKS containing issuer runtime-compatible EC keys.
 *
 * The issuer runtime requires:
 * - one ES256 signing key (use=sig)
 * - one ECDH-ES encryption key (use=enc)
 *
 * @returns A JSON string representing the issuer JWKS.
 */
export function getSigningKeys(): string {
  const signing = generateEcPrivateJwk({
    kid: 'issuer-signing-key',
    use: 'sig',
    alg: 'ES256',
    keyOps: ['sign']
  });

  const encryption = generateEcPrivateJwk({
    kid: 'issuer-encryption-key',
    use: 'enc',
    alg: 'ECDH-ES',
    keyOps: ['deriveKey']
  });

  return JSON.stringify({ keys: [...signing.keys, ...encryption.keys] }, null, 2);
}

/** Generates and returns an EC P-256 private key JWK for
 * authentication request signing.
 *
 * @returns A JSON string representing the EC P-256 private key JWK.
 */
export function getAuthRequestKey(): string {
  const jwk = generateEcPrivateJwk({
    kid: 'auth-request-key',
    use: 'sig',
    alg: 'ES256',
    keyOps: ['sign']
  });

  return JSON.stringify(jwk.keys[0], null, 2);
}

/** Generates and returns an EC P-256 private key JWK for
 * authentication response encryption.
 *
 * @returns A JSON string representing the EC P-256 private key JWK.
 */
export function getAuthResponseKey(): string {
  const jwk = generateEcPrivateJwk({
    kid: 'auth-response-key',
    use: 'enc',
    alg: 'ECDH-ES',
    keyOps: ['deriveKey']
  });

  return JSON.stringify(jwk.keys[0], null, 2);
}

/** Generates and returns an EC P-256 private key JWK for federation entity-statement signing. */
export function getFederationKey(): string {
  const jwk = generateEcPrivateJwk({
    kid: 'federation-key',
    use: 'sig',
    alg: 'ES256',
    keyOps: ['sign']
  });

  return JSON.stringify(jwk.keys[0], null, 2);
}
