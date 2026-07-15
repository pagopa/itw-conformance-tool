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
  issuerIntermediateCertPem: string;
};

declare module 'fastify' {
  interface FastifyInstance {
    issuerKeys: IssuerKeys;
  }
}

const REQUIRED_FILES = ['jwks.json', 'cert.pem', 'intermediate-cert.pem'] as const;

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

function hasCompatibleEcEncryptionKey(keys: StoredJwk[]): boolean {
  return keys.some(
    (jwk) => isEcPrivateJwk(jwk) && jwk.use === 'enc' && (jwk.alg === undefined || jwk.alg === 'ECDH-ES')
  );
}

function hasCompatibleIssuerJwks(jwks: unknown): boolean {
  const keys = (jwks as { keys?: StoredJwk[] }).keys;
  if (!Array.isArray(keys)) {
    return false;
  }

  return findEcSigningKey(keys) !== undefined && hasCompatibleEcEncryptionKey(keys);
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
 * (`itw-conformance-tool init`), which generates `jwks.json`, `cert.pem`, and
 * `intermediate-cert.pem` together as a linked, cryptographically consistent
 * set. The runtime must never regenerate only one of these artifacts, since
 * doing so would silently break the binding between the issuer signing key
 * and its certificate. Any missing or incompatible file therefore fails
 * startup with an actionable remediation message instead.
 *
 * @param dir - The directory where the required issuer key material files should be located
 * @returns An object containing the contents of the JWKS and PEM files
 * @throws {Error} If any required file is missing
 */
async function readRequiredKeyMaterial(dir: string): Promise<{
  jwks: string;
  certPem: string;
  intermediateCertPem: string;
}> {
  const paths = REQUIRED_FILES.map((f) => path.join(dir, f));
  const [jwks, certPem, intermediateCertPem] = await Promise.all(paths.map(readOptional));

  const missing = REQUIRED_FILES.filter((_, index) => [jwks, certPem, intermediateCertPem][index] === null);
  if (missing.length > 0) {
    throw new Error(
      `Missing required issuer key material in '${dir}': ${missing.join(', ')}. ` +
        `Run 'itw-conformance-tool init' to generate the issuer signing keys and certificate chain.`
    );
  }

  return {
    jwks: jwks as string,
    certPem: certPem as string,
    intermediateCertPem: intermediateCertPem as string
  };
}

export default fp(
  async function keysPlugin(app) {
    const keysDir = path.join(app.config.DATA_DIR, 'issuer');

    const { jwks, certPem, intermediateCertPem } = await readRequiredKeyMaterial(keysDir);

    const parsedJwks = JSON.parse(jwks);
    await validateJWKS(parsedJwks);

    if (!hasCompatibleIssuerJwks(parsedJwks)) {
      throw new Error(
        `Issuer JWKS in '${path.join(keysDir, 'jwks.json')}' is incompatible with ES256/ECDH-ES runtime requirements. ` +
          `Run 'itw-conformance-tool init --force' to regenerate the issuer key material and certificate chain together.`
      );
    }

    const signingJwk = findEcSigningKey(parsedJwks.keys) as StoredJwk;
    await validateCertificateMatchesJwk(certPem, signingJwk as unknown as JWK);

    app.decorate('issuerKeys', {
      signingKeysJwks: parsedJwks,
      issuerCertPem: certPem,
      issuerIntermediateCertPem: intermediateCertPem
    });
  },
  { name: 'keys', dependencies: ['config'] }
);
