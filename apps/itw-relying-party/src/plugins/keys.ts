import { createPrivateKey } from 'node:crypto';
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

const KEY_FILES = [
  { key: 'authRequestPrivateKeyPem', file: 'rp/auth-request-key.jwk.json' },
  { key: 'authResponsePrivateKeyPem', file: 'rp/auth-response-key.jwk.json' }
] as const;

async function loadKeyFile(dataDir: string, fileName: string): Promise<string> {
  const keyPath = resolve(dataDir, fileName);
  let content: string;

  try {
    content = await readFile(keyPath, 'utf8');
  } catch {
    throw new Error(
      `Missing required auth key: ${fileName} not found in ${dataDir}. ` +
        `Please ensure the key file exists before starting the server.`
    );
  }

  try {
    const jwk = JSON.parse(content);
    // Convert JWK to PEM PKCS8
    const privateKey = createPrivateKey({ key: jwk, format: 'jwk' });
    const pem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
    return pem;
  } catch (err) {
    throw new Error(
      `Invalid auth key format in ${fileName}: ${err instanceof Error ? err.message : String(err)}. ` +
        `Please ensure the key file contains a valid JWK.`
    );
  }
}

export default fp(
  async function keysPlugin(app) {
    const { dataDir } = app.config;

    const [authRequestPrivateKeyPem, authResponsePrivateKeyPem] = await Promise.all(
      KEY_FILES.map((kf) => loadKeyFile(dataDir, kf.file))
    );

    app.decorate('rpKeys', {
      authRequestPrivateKeyPem,
      authResponsePrivateKeyPem
    });
  },
  { name: 'keys', dependencies: ['config'] }
);
