import { generateEcPrivateJwk, generateSigningJwks } from '@itw-conformance-tool/crypto';

// Generates and returns a JWK Set containing a single RSA signing key for the issuer.
export function getSigningKeys(): string {
  return generateSigningJwks({ kid: 'issuer-signing-key', use: 'sig' });
}

// Generates and returns an EC P-256 private key JWK for authentication request signing.
export function getAuthRequestKey(): string {
  return generateEcPrivateJwk({
    kid: 'auth-request-key',
    use: 'sig',
    alg: 'ES256',
    keyOps: ['sign']
  });
}

// Generates and returns an EC P-256 private key JWK for authentication response decryption.
export function getAuthResponseKey(): string {
  return generateEcPrivateJwk({
    kid: 'auth-response-key',
    use: 'enc',
    alg: 'ECDH-ES',
    keyOps: ['decrypt']
  });
}
