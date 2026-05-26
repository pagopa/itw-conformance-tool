import { readFile, rename, writeFile } from 'node:fs/promises';
import path from 'node:path';

import fp from 'fastify-plugin';

import { validateIACAKeyPair, validateJWKS } from '#/utils/validate.js';

import { generateIaca, generateJwks } from '../crypto/auto-keygen.js';

export type IssuerKeys = {
  signingKeysJwks: {
    keys: Array<{
      kty: string;
      kid: string;
      alg?: string;
      d?: string;
    }>;
  };
  iacaCertPem: string;
  iacaKeyPem: string;
};

declare module 'fastify' {
  interface FastifyInstance {
    issuerKeys: IssuerKeys;
  }
}

const REQUIRED_FILES = ['signing-keys.jwks.json', 'iaca-cert.pem', 'iaca-key.pem'] as const;

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

function hasCompatibleEcSigningKey(keys: StoredJwk[]): boolean {
  return keys.some(
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

  return hasCompatibleEcSigningKey(keys) && hasCompatibleEcEncryptionKey(keys);
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

/** Ensures that the required key material files exist
 * in the specified directory, generating them if necessary,
 * and reads their contents
 *
 * @param dir - The directory where the key material files should be located
 * @returns An object containing the contents of the JWKS and PEM files
 */
async function ensureKeyMaterialExists(dir: string): Promise<{
  jwks: string;
  certPem: string;
  keyPem: string;
}> {
  const [jwksPath, certPath, keyPath] = REQUIRED_FILES.map((f) => path.join(dir, f));

  let [jwks, certPem, keyPem] = await Promise.all([
    readOptional(jwksPath),
    readOptional(certPath),
    readOptional(keyPath)
  ]);

  if (certPem === null || keyPem === null) {
    // If either file is missing, regenerate both — cert and key are a matched cryptographic pair.
    // Write to temp files first, then rename atomically to avoid a partial pair on crash.
    const generatedIaca = await generateIaca();
    const certTmp = `${certPath}.tmp`;
    const keyTmp = `${keyPath}.tmp`;
    await Promise.all([
      writeFile(certTmp, generatedIaca.certPem, 'utf8'),
      writeFile(keyTmp, generatedIaca.keyPem, 'utf8')
    ]);
    await Promise.all([rename(certTmp, certPath), rename(keyTmp, keyPath)]);
    certPem = generatedIaca.certPem;
    keyPem = generatedIaca.keyPem;
  }

  if (jwks === null) {
    const generated = await generateJwks();
    const jwksTmp = `${jwksPath}.tmp`;
    await writeFile(jwksTmp, generated, 'utf8');
    await rename(jwksTmp, jwksPath);
    jwks = generated;
  }

  return { jwks, certPem, keyPem };
}

export default fp(
  async function keysPlugin(app) {
    const keysDir = path.join(app.config.DATA_DIR, 'issuer');
    const jwksPath = path.join(keysDir, 'signing-keys.jwks.json');

    const { jwks, certPem, keyPem } = await ensureKeyMaterialExists(keysDir);

    let parsedJwks = JSON.parse(jwks);
    await validateJWKS(parsedJwks);

    if (!hasCompatibleIssuerJwks(parsedJwks)) {
      app.log.warn('Issuer JWKS is incompatible with ES256/ECDH-ES runtime requirements; regenerating key material');

      const regeneratedJwks = await generateJwks();
      const jwksTmp = `${jwksPath}.tmp`;
      await writeFile(jwksTmp, regeneratedJwks, 'utf8');
      await rename(jwksTmp, jwksPath);

      parsedJwks = JSON.parse(regeneratedJwks);
      await validateJWKS(parsedJwks);
    }

    await validateIACAKeyPair(certPem, keyPem);

    app.decorate('issuerKeys', {
      signingKeysJwks: parsedJwks,
      iacaCertPem: certPem,
      iacaKeyPem: keyPem
    });
  },
  { name: 'keys', dependencies: ['config'] }
);
