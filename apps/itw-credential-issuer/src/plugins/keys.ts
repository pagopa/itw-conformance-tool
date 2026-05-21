import { constants } from 'node:fs';
import { access, readFile } from 'node:fs/promises';
import path from 'node:path';

import fp from 'fastify-plugin';

type SigningJwks = {
  keys: unknown[];
};

type IssuerKeys = {
  signingKeysJwks: SigningJwks;
  iacaCertPem: string;
  iacaKeyPem: string;
};

declare module 'fastify' {
  interface FastifyInstance {
    issuerKeys: IssuerKeys;
  }
}

const REQUIRED_FILES = ['signing-keys.jwks.json', 'iaca-cert.pem', 'iaca-key.pem'] as const;

async function ensureReadable(filePath: string): Promise<void> {
  try {
    await access(filePath, constants.R_OK);
  } catch (error) {
    const errno = (error as NodeJS.ErrnoException).code;
    const suffix = errno ? ` (${errno})` : '';
    throw new Error(`Required key material file is missing or not readable: ${filePath}${suffix}`);
  }
}

async function areAllRequiredFilesReadable(dirPath: string): Promise<boolean> {
  try {
    await Promise.all(REQUIRED_FILES.map((fileName) => ensureReadable(path.join(dirPath, fileName))));
    return true;
  } catch {
    return false;
  }
}

function parseJwks(content: string, filePath: string): SigningJwks {
  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    throw new Error(`Invalid JSON in ${filePath}`);
  }

  if (typeof parsed !== 'object' || parsed === null || !('keys' in parsed) || !Array.isArray(parsed.keys)) {
    throw new Error(`Invalid JWKS in ${filePath}: expected an object with a keys array`);
  }

  if (parsed.keys.length === 0) {
    throw new Error(`Invalid JWKS in ${filePath}: keys array must not be empty`);
  }

  return parsed as SigningJwks;
}

export default fp(
  async function keysPlugin(app) {
    const candidateDirs =
      app.config.KEYS_DIR !== undefined
        ? [app.config.KEYS_DIR]
        : [path.join(app.config.DATA_DIR, 'itw-credential-issuer'), app.config.DATA_DIR];

    let keysDir: string | undefined;
    for (const candidateDir of candidateDirs) {
      if (await areAllRequiredFilesReadable(candidateDir)) {
        keysDir = candidateDir;
        break;
      }
    }

    if (keysDir === undefined) {
      const searched = candidateDirs.map((candidateDir) => path.join(candidateDir, '<required-file>')).join(', ');
      throw new Error(`Required key material file is missing or not readable. Searched: ${searched}`);
    }

    const filePaths = REQUIRED_FILES.map((fileName) => path.join(keysDir, fileName));

    await Promise.all(filePaths.map((filePath) => ensureReadable(filePath)));

    const [jwksContent, certPem, keyPem] = await Promise.all([
      readFile(filePaths[0], 'utf8'),
      readFile(filePaths[1], 'utf8'),
      readFile(filePaths[2], 'utf8')
    ]);

    app.decorate('issuerKeys', {
      signingKeysJwks: parseJwks(jwksContent, filePaths[0]),
      iacaCertPem: certPem,
      iacaKeyPem: keyPem
    });
  },
  { name: 'keys', dependencies: ['config'] }
);
