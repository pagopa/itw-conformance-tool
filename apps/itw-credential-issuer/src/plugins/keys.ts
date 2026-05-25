import { readFile, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';

import fp from 'fastify-plugin';

import { generateIaca, generateJwks } from '../crypto/auto-keygen.js';

export type IssuerKeys = {
  signingKeysJwks: string;
  iacaCertPem: string;
  iacaKeyPem: string;
};

declare module 'fastify' {
  interface FastifyInstance {
    issuerKeys: IssuerKeys;
  }
}

const REQUIRED_FILES = ['signing-keys.jwks.json', 'iaca-cert.pem', 'iaca-key.pem'] as const;

/** Reads a file, returning null if it does not exist. */
async function readOptional(filePath: string): Promise<string | null> {
  try {
    return await readFile(filePath, 'utf8');
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw err;
  }
}

/**
 * Writes content to a file exclusively (creates only — does not overwrite).
 * If the file was already created concurrently, reads and returns the existing content.
 */
async function writeExclusive(filePath: string, content: string): Promise<string> {
  try {
    await writeFile(filePath, content, { encoding: 'utf8', flag: 'wx' });
    return content;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'EEXIST') {
      return readFile(filePath, 'utf8');
    }
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
    const generatedIaca = await generateIaca();
    [certPem, keyPem] = await Promise.all([
      writeExclusive(certPath, generatedIaca.certPem),
      writeExclusive(keyPath, generatedIaca.keyPem)
    ]);
  }

  jwks ??= await writeExclusive(jwksPath, await generateJwks());

  return { jwks, certPem, keyPem };
}

export default fp(
  async function keysPlugin(app) {
    const keysDir = path.join(app.config.DATA_DIR, 'issuer');

    try {
      const dirStat = await stat(keysDir);
      if (!dirStat.isDirectory()) {
        throw new Error(`Issuer path is not a directory: ${keysDir}`);
      }
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
        throw new Error(`Issuer directory does not exist: ${keysDir}`);
      }
      throw err;
    }

    const { jwks, certPem, keyPem } = await ensureKeyMaterialExists(keysDir);
    app.decorate('issuerKeys', {
      signingKeysJwks: jwks,
      iacaCertPem: certPem,
      iacaKeyPem: keyPem
    });
  },
  { name: 'keys', dependencies: ['config'] }
);
