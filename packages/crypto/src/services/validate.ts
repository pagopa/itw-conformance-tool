import { createPrivateKey, createPublicKey } from 'node:crypto';

import { X509Certificate } from '@peculiar/x509';
import { importJWK, type JWK } from 'jose';

import { jwkSchema, jwksSchema } from '../schemas/jwk.js';

/** Validates that a JWK object conforms to the required structure and can be
 * cryptographically imported. Accepts keys with `use: 'sig'`, `use: 'enc'`, or
 * no `use` claim (e.g. federation-level signing keys).
 *
 * @param key - The JWK to validate
 * @returns true if the key is a structurally valid and importable JWK, false otherwise
 */
export async function isValidJwk(key: unknown): Promise<boolean> {
  const parsed = jwkSchema.safeParse(key);
  if (!parsed.success) return false;

  try {
    await importJWK(parsed.data as JWK, parsed.data.alg);
    return true;
  } catch {
    return false;
  }
}

/** Validates a JWK Set (JWKS) for structural correctness and
 * cryptographic integrity.
 *
 * @param jwks - The value to validate (typically the result of `JSON.parse` on a stored JWKS file).
 */
export async function validateJWKS(jwks: unknown): Promise<void> {
  const parsed = jwksSchema.parse(jwks);

  const seenKids = new Set<string>();
  for (const key of parsed.keys) {
    if (seenKids.has(key.kid)) {
      throw new Error(`Duplicate kid found in JWKS: ${key.kid}`);
    }

    seenKids.add(key.kid);

    if (key.use === 'enc' && key.alg === undefined) {
      throw new Error(`Key with kid '${key.kid}' has use=enc but no alg specified`);
    }

    await importJWK(key as JWK, key.alg);
  }
}

/** Parses a PEM private key into a Node.js KeyObject.
 * Supports both "BEGIN PRIVATE KEY" (PKCS#8) and "BEGIN EC PRIVATE KEY" (SEC1).
 *
 * @param keyPem - The PEM-encoded private key string
 * @returns A Node.js KeyObject representing the private key
 * @throws {Error} If the key format is invalid or cannot be parsed
 */
function parseIacaPrivateKey(keyPem: string): ReturnType<typeof createPrivateKey> {
  try {
    return createPrivateKey(keyPem);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Invalid IACA private key format. Expected a valid PEM private key (PKCS#8 or SEC1). ${message}`);
  }
}

type ExportedPublicJwk = {
  kty?: string;
  crv?: string;
  x?: string;
  y?: string;
  n?: string;
  e?: string;
};

/** Returns a stable identifier for public JWK coordinates/modulus for key-pair matching.
 * Generates a unique string representation based on the key type and its public parameters.
 *
 * @param jwk - The exported public JWK object
 * @returns A stable identifier string for the JWK coordinates
 * @throws {Error} If the JWK is missing required parameters or has an unsupported key type
 */
function publicJwkIdentity(jwk: ExportedPublicJwk): string {
  switch (jwk.kty) {
    case 'EC': {
      if (!jwk.crv || !jwk.x || !jwk.y) {
        throw new Error('Invalid EC JWK: missing crv/x/y');
      }

      return `EC:${jwk.crv}:${jwk.x}:${jwk.y}`;
    }
    case 'RSA': {
      if (!jwk.n || !jwk.e) {
        throw new Error('Invalid RSA JWK: missing n/e');
      }

      return `RSA:${jwk.n}:${jwk.e}`;
    }
    case 'OKP': {
      if (!jwk.crv || !jwk.x) {
        throw new Error('Invalid OKP JWK: missing crv/x');
      }

      return `OKP:${jwk.crv}:${jwk.x}`;
    }
    default:
      throw new Error(`Unsupported IACA key type: ${String(jwk.kty)}`);
  }
}

/** Validates that an IACA X.509 certificate and private key form a valid cryptographic pair.
 * Ensures that the public key extracted from the certificate matches the public key
 * derived from the private key.
 *
 * @param certPem - The PEM-encoded X.509 certificate
 * @param keyPem - The PEM-encoded private key (PKCS#8 or SEC1 format)
 * @throws {Error} If the certificate and private key do not form a valid pair, or if either is invalid
 */
export async function validateIACAKeyPair(certPem: string, keyPem: string): Promise<void> {
  const cert = new X509Certificate(certPem);

  const privateKey = parseIacaPrivateKey(keyPem);
  const publicFromPrivate = createPublicKey(privateKey).export({ format: 'jwk' }) as ExportedPublicJwk;
  const publicFromCert = createPublicKey(cert.toString()).export({ format: 'jwk' }) as ExportedPublicJwk;

  if (publicJwkIdentity(publicFromPrivate) !== publicJwkIdentity(publicFromCert)) {
    throw new Error('IACA certificate and private key do not correspond');
  }
}
