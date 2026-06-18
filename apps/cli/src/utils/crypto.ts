import { generateKeyPairSync } from 'node:crypto';

function generateEcPrivateJwk(descriptor: {
  alg: 'ES256' | 'ECDH-ES';
  keyOps: string[];
  kid: string;
  use: 'sig' | 'enc';
}): { keys: Record<string, unknown>[] } {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const privateJwk = privateKey.export({ format: 'jwk' }) as Record<string, unknown>;

  return {
    keys: [
      {
        ...privateJwk,
        kid: descriptor.kid,
        alg: descriptor.alg,
        use: descriptor.use,
        key_ops: descriptor.keyOps
      }
    ]
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
 * authentication response decryption.
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
