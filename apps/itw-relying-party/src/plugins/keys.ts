import { X509Certificate, createPrivateKey } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

import fp from 'fastify-plugin';

type RpKeys = {
  authRequestPrivateKeyPem: string;
  authResponsePrivateKeyPem: string;
  signingPrivateKeyPem: string;
  x5cCertPem: string;
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
    const jwk = await JSON.parse(content);
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

async function loadSigningKey(signingKeyPath: string): Promise<string> {
  let content: string;

  try {
    content = await readFile(signingKeyPath, 'utf8');
  } catch {
    throw new Error(
      `Missing required signing key: file not found at ${signingKeyPath}. ` +
        `Please ensure the signing key file exists before starting the server.`
    );
  }

  try {
    // Auto-detect format: try JWK (JSON) first, then treat as PEM
    let keyInput: Parameters<typeof createPrivateKey>[0];
    const trimmed = content.trim();
    if (trimmed.startsWith('{')) {
      const jwk = await JSON.parse(trimmed);
      keyInput = { key: jwk, format: 'jwk' };
    } else {
      keyInput = { key: trimmed, format: 'pem' };
    }
    const privateKey = createPrivateKey(keyInput);
    const pem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
    return pem;
  } catch (err) {
    throw new Error(
      `Invalid signing key at ${signingKeyPath}: ${err instanceof Error ? err.message : String(err)}. ` +
        `Please ensure the file contains a valid PEM or JWK private key.`
    );
  }
}

async function loadX5cCert(x5cCertPath: string): Promise<string> {
  let content: string;

  try {
    content = await readFile(x5cCertPath, 'utf8');
  } catch {
    throw new Error(
      `Missing required x5c certificate: file not found at ${x5cCertPath}. ` +
        `Please ensure the certificate file exists before starting the server.`
    );
  }

  try {
    new X509Certificate(content);
  } catch (err) {
    throw new Error(
      `Invalid x5c certificate at ${x5cCertPath}: ${err instanceof Error ? err.message : String(err)}. ` +
        `Please ensure the file contains a valid PEM certificate chain.`
    );
  }

  return content;
}

export default fp(
  async function keysPlugin(app) {
    const { signingKeyPath, x5cCertPath, dataDir } = app.config;

    const [authRequestPrivateKeyPem, authResponsePrivateKeyPem, signingPrivateKeyPem, x5cCertPem] = await Promise.all([
      ...KEY_FILES.map((kf) => loadKeyFile(dataDir, kf.file)),
      loadSigningKey(signingKeyPath),
      loadX5cCert(x5cCertPath)
    ]);

    app.decorate('rpKeys', {
      authRequestPrivateKeyPem,
      authResponsePrivateKeyPem,
      signingPrivateKeyPem,
      x5cCertPem
    });
  },
  { name: 'keys', dependencies: ['config'] }
);
