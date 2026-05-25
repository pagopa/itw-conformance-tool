import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

import fp from 'fastify-plugin';

type RpKeys = {
  authRequestPrivateKeyPem: string;
  authResponsePrivateKeyPem: string;
};

declare module 'fastify' {
  interface FastifyInstance {
    rpKeys: RpKeys;
  }
}

const KEY_FILES = ['authRequestPrivateKey', 'authResponsePrivateKey'] as const;

async function loadKeyFile(dataDir: string, keyName: string): Promise<string> {
  const keyPath = resolve(dataDir, keyName);
  let content: string;

  try {
    content = await readFile(keyPath, 'utf8');
  } catch {
    throw new Error(
      `Missing required auth key: ${keyName} not found in ${dataDir}. ` +
        `Please ensure the key file exists before starting the server.`
    );
  }

  if (content.trim().length === 0) {
    throw new Error(
      `Invalid auth key: ${keyName} in ${dataDir} is empty. ` + `Please ensure the key file contains valid content.`
    );
  }

  return content;
}

export default fp(
  async function keysPlugin(app) {
    const { dataDir } = app.config;

    const [authRequestPrivateKeyPem, authResponsePrivateKeyPem] = await Promise.all(
      KEY_FILES.map((keyName) => loadKeyFile(dataDir, keyName))
    );

    app.decorate('rpKeys', {
      authRequestPrivateKeyPem,
      authResponsePrivateKeyPem
    });
  },
  { name: 'keys', dependencies: ['config'] }
);
