import { createPublicKey, type JsonWebKey } from 'node:crypto';

import { zJwk, zJwkSet } from '@pagopa/io-wallet-oauth2';
import { X509Certificate } from '@peculiar/x509';
import { importJWK, type JWK } from 'jose';

/** Validates that a JWK object conforms to the required structure and can be
 * cryptographically imported. Accepts keys with `use: 'sig'`, `use: 'enc'`, or
 * no `use` claim (e.g. federation-level signing keys).
 *
 * @param key - The JWK to validate
 * @returns true if the key is a structurally valid and importable JWK, false otherwise
 */
export async function isValidJwk(key: unknown): Promise<boolean> {
  const parsed = zJwk.safeParse(key);
  if (!parsed.success) return false;
  if (parsed.data.use === 'enc' && parsed.data.alg === undefined) return false;

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
  const parsed = zJwkSet.parse(jwks);

  const seenKids = new Set<string>();
  for (const key of parsed.keys) {
    if (!key.kid) {
      throw new Error('Key in JWKS is missing "kid" property');
    }
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
      throw new Error(`Unsupported key type: ${String(jwk.kty)}`);
  }
}

/** Removes private key material and key_ops from a JWK to produce a public-only JWK,
 * suitable for import as a public key.
 *
 * @param jwk - The input JWK, which may contain private key parameters and/or key_ops.
 * @returns A new JWK object containing only the public key parameters and no key_ops.
 */
function stripPrivateKeyMaterial(jwk: JWK): JsonWebKey {
  const { d: _d, key_ops: _keyOps, ...publicJwk } = jwk;
  return { ...publicJwk };
}

/** Validates that an X.509 certificate's public key corresponds to the public key
 * of the given JWK. Used to enforce the invariant that a persisted issuer
 * certificate binds the same key pair used to produce a signature, regardless of
 * whether the certificate is self-signed or issued by an intermediate CA.
 *
 * @param certPem - The PEM-encoded X.509 certificate
 * @param jwk - The JWK (private or public) whose public key must match the certificate's public key
 * @throws {Error} If the certificate and JWK do not share the same public key, or if either is invalid
 */
export async function validateCertificateMatchesJwk(certPem: string, jwk: JWK): Promise<void> {
  let cert: X509Certificate;
  try {
    cert = new X509Certificate(certPem);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Invalid certificate format. Expected a valid PEM X.509 certificate. ${message}`);
  }

  let publicFromJwk: ExportedPublicJwk;
  try {
    publicFromJwk = createPublicKey({ format: 'jwk', key: stripPrivateKeyMaterial(jwk) }).export({
      format: 'jwk'
    }) as ExportedPublicJwk;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Invalid signing JWK public key material. ${message}`);
  }

  const publicFromCert = createPublicKey(cert.toString()).export({ format: 'jwk' }) as ExportedPublicJwk;

  if (publicJwkIdentity(publicFromJwk) !== publicJwkIdentity(publicFromCert)) {
    throw new Error('Certificate public key does not correspond to the provided signing JWK');
  }
}
