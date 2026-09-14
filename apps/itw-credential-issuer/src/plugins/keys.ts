import { readFile } from 'node:fs/promises';
import path from 'node:path';

import { validateCertificateMatchesJwk, validateJWKS } from '@itw-conformance-tool/crypto';
import fp from 'fastify-plugin';

import type { JWK } from 'jose';

export type IssuerKeys = {
  signingKeysJwks: {
    keys: Array<{
      kty: string;
      kid: string;
      alg?: string;
      d?: string;
    }>;
  };
  issuerCertPem: string;
  /**
   * The certificate for the ECDH-ES key in `jwks.json` — the key a wallet
   * encrypts an Authorization Response to when the Credential Issuer acts as a
   * verifier. Issued by the same intermediate CA as `issuerCertPem`, so both
   * keys the issuer publishes root at the Trust Anchor certificate.
   */
  issuerEncryptionCertPem: string;
  issuerIntermediateCertPem: string;
};

declare module 'fastify' {
  interface FastifyInstance {
    issuerKeys: IssuerKeys;
  }
}

const REQUIRED_FILES = ['jwks.json', 'cert.pem', 'enc-cert.pem', 'intermediate-cert.pem'] as const;

type StoredJwk = {
  kty?: string;
  use?: string;
  alg?: string;
  d?: string;
  crv?: string;
  x?: string;
  y?: string;
};

function isEcPrivateJwk(jwk: StoredJwk): boolean {
  return (
    jwk.kty === 'EC' &&
    typeof jwk.d === 'string' &&
    typeof jwk.crv === 'string' &&
    typeof jwk.x === 'string' &&
    typeof jwk.y === 'string'
  );
}

function findEcSigningKey(keys: StoredJwk[]): StoredJwk | undefined {
  return keys.find(
    (jwk) =>
      isEcPrivateJwk(jwk) &&
      (jwk.use === undefined || jwk.use === 'sig') &&
      (jwk.alg === undefined || jwk.alg.startsWith('ES'))
  );
}

function findEcEncryptionKey(keys: StoredJwk[]): StoredJwk | undefined {
  return keys.find(
    (jwk) => isEcPrivateJwk(jwk) && jwk.use === 'enc' && (jwk.alg === undefined || jwk.alg === 'ECDH-ES')
  );
}

function hasCompatibleIssuerJwks(jwks: unknown): boolean {
  const keys = (jwks as { keys?: StoredJwk[] }).keys;
  if (!Array.isArray(keys)) {
    return false;
  }

  return findEcSigningKey(keys) !== undefined && findEcEncryptionKey(keys) !== undefined;
}

/** Reads a file, returning null if it does not exist. */
async function readOptional(filePath: string): Promise<string | null> {
  try {
    return await readFile(filePath, 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw err;
  }
}

/** Reads the required issuer key material files from the specified directory.
 *
 * Issuer key/certificate generation is owned exclusively by CLI initialization
 * (`itw-conformance-tool init`), which generates `jwks.json`, `cert.pem`,
 * `enc-cert.pem`, and `intermediate-cert.pem` together as a linked,
 * cryptographically consistent set. The runtime must never regenerate only one
 * of these artifacts, since doing so would silently break the binding between
 * an issuer key and the certificate published beside it. Any missing or
 * incompatible file therefore fails startup with an actionable remediation
 * message instead.
 *
 * @param dir - The directory where the required issuer key material files should be located
 * @returns The contents of each required file, keyed by its name
 * @throws {Error} If any required file is missing
 */
async function readRequiredKeyMaterial(dir: string): Promise<Record<(typeof REQUIRED_FILES)[number], string>> {
  const contents = await Promise.all(REQUIRED_FILES.map((file) => readOptional(path.join(dir, file))));

  const missing = REQUIRED_FILES.filter((_, index) => contents[index] === null);
  if (missing.length > 0) {
    throw new Error(
      `Missing required issuer key material in '${dir}': ${missing.join(', ')}. ` +
        `Run 'itw-conformance-tool init' to generate the issuer signing keys and certificate chain.`
    );
  }

  return Object.fromEntries(REQUIRED_FILES.map((file, index) => [file, contents[index] as string])) as Record<
    (typeof REQUIRED_FILES)[number],
    string
  >;
}

export default fp(
  async function keysPlugin(app) {
    const keysDir = path.join(app.config.DATA_DIR, 'issuer');

    const material = await readRequiredKeyMaterial(keysDir);

    const parsedJwks = JSON.parse(material['jwks.json']);
    await validateJWKS(parsedJwks);

    if (!hasCompatibleIssuerJwks(parsedJwks)) {
      throw new Error(
        `Issuer JWKS in '${path.join(keysDir, 'jwks.json')}' is incompatible with ES256/ECDH-ES runtime requirements. ` +
          `Run 'itw-conformance-tool init --force' to regenerate the issuer key material and certificate chain together.`
      );
    }

    // Each certificate is checked against the key it will be published beside.
    // A certificate for a key the issuer no longer holds is a mismatch a wallet
    // could only discover as a signature that will not verify, or as a response
    // encrypted to a key nobody can decrypt with.
    const signingJwk = findEcSigningKey(parsedJwks.keys) as StoredJwk;
    const encryptionJwk = findEcEncryptionKey(parsedJwks.keys) as StoredJwk;
    await Promise.all([
      validateCertificateMatchesJwk(material['cert.pem'], signingJwk as unknown as JWK),
      validateCertificateMatchesJwk(material['enc-cert.pem'], encryptionJwk as unknown as JWK)
    ]);

    app.decorate('issuerKeys', {
      signingKeysJwks: parsedJwks,
      issuerCertPem: material['cert.pem'],
      issuerEncryptionCertPem: material['enc-cert.pem'],
      issuerIntermediateCertPem: material['intermediate-cert.pem']
    });
  },
  { name: 'keys', dependencies: ['config'] }
);
