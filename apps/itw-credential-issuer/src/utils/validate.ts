import { createPrivateKey, createPublicKey } from 'node:crypto';

import { X509Certificate } from '@peculiar/x509';
import { importJWK, type JWK } from 'jose';
import { z } from 'zod';

const jwkSchema = z.looseObject({
  kty: z.string(),
  kid: z.string().min(1),
  use: z.enum(['sig', 'enc']).optional(),
  alg: z.string().optional(),
  key_ops: z.array(z.string()).optional(),

  // RSA fields
  n: z.string().optional(),
  e: z.string().optional(),

  // EC / OKP private key scalar
  d: z.string().optional(),

  // EC / OKP public key coordinates
  x: z.string().optional(),
  y: z.string().optional(),
  crv: z.string().optional()
});

const jwksSchema = z.object({
  keys: z.array(jwkSchema).min(1)
});

/** Validates a JWK Set (JWKS) for structural correctness and
 * cryptographic integrity
 *
 * @param jwks - The value to validate (typically the result of `JSON.parse` on the stored JWKS file)
 * @returns A promise that resolves if the JWKS is valid, or rejects with an error describing the validation failure
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

/**
 * Normalizes a PEM private key to PKCS#8 DER so it can be imported by WebCrypto.
 * Supports both "BEGIN PRIVATE KEY" (PKCS#8) and "BEGIN EC PRIVATE KEY" (SEC1).
 */
function toPkcs8Der(keyPem: string): Buffer {
  try {
    const keyObject = createPrivateKey(keyPem);
    const der = keyObject.export({ format: 'der', type: 'pkcs8' });
    return Buffer.isBuffer(der) ? der : Buffer.from(der as ArrayBuffer);
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

/** Returns a stable identifier for public JWK coordinates/modulus for key-pair matching. */
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

/** Validates that an IACA X.509 certificate and private key form a valid cryptographic pair. */
export async function validateIACAKeyPair(certPem: string, keyPem: string): Promise<void> {
  const cert = new X509Certificate(certPem);

  const privateKey = createPrivateKey({ key: toPkcs8Der(keyPem), format: 'der', type: 'pkcs8' });
  const publicFromPrivate = createPublicKey(privateKey).export({ format: 'jwk' }) as ExportedPublicJwk;
  const publicFromCert = createPublicKey(cert.toString()).export({ format: 'jwk' }) as ExportedPublicJwk;

  if (publicJwkIdentity(publicFromPrivate) !== publicJwkIdentity(publicFromCert)) {
    throw new Error('IACA certificate and private key do not correspond');
  }
}
