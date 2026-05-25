import { existsSync } from 'node:fs';
import { readFile, writeFile } from 'node:fs/promises';
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
  const resolvedPaths = REQUIRED_FILES.map((fileName) => path.join(dir, fileName));

  const [jwksPath, certPath, keyPath] = resolvedPaths;
  const missingFiles = resolvedPaths.filter((filePath) => !existsSync(filePath));

  if (missingFiles.length > 0) {
    if (!existsSync(certPath) || !existsSync(keyPath)) {
      const generatedIaca = await generateIaca();

      await writeFile(certPath, generatedIaca.certPem, 'utf8');
      await writeFile(keyPath, generatedIaca.keyPem, 'utf8');
    }

    if (!existsSync(jwksPath)) {
      const generatedJwks = await generateJwks();

      await writeFile(jwksPath, generatedJwks, 'utf8');
    }
  }

  const [jwks, certPem, keyPem] = await Promise.all([
    readFile(jwksPath, 'utf8'),
    readFile(certPath, 'utf8'),
    readFile(keyPath, 'utf8')
  ]);

  return {
    jwks,
    certPem,
    keyPem
  };
}

export default fp(
  async function keysPlugin(app) {
    const keysDir = path.join(app.config.DATA_DIR, 'issuer');
    if (!existsSync(keysDir)) {
      throw new Error(`Issuer directory does not exist: ${keysDir}`);
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
