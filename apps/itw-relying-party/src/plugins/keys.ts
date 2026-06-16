import { X509Certificate, createPrivateKey, type JsonWebKey } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

import fp from 'fastify-plugin';

const CERT_PEM_PATTERN = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;

type RpKeys = {
  authRequestPrivateKeyPem: string;
  authResponsePrivateKeyPem: string;
  federationPrivateKeyPem: string;
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
  { key: 'authResponsePrivateKeyPem', file: 'rp/auth-response-key.jwk.json' },
  { key: 'federationPrivateKeyPem', file: 'rp/federation-key.jwk.json' }
] as const;

async function loadKeyFile(dataDir: string, fileName: string): Promise<string> {
  const keyPath = resolve(dataDir, fileName);
  let content: string;

  try {
    content = await readFile(keyPath, 'utf8');
  } catch {
    throw new Error(
      `Missing required key: ${fileName} not found in ${dataDir}. ` +
        `Please ensure the key file exists before starting the server.`
    );
  }

  try {
    const firstPass = JSON.parse(content) as unknown;
    const jwk = typeof firstPass === 'string' ? (JSON.parse(firstPass) as unknown) : firstPass;

    if (!jwk || typeof jwk !== 'object' || Array.isArray(jwk)) {
      throw new Error('JWK payload must be a JSON object');
    }

    // Convert JWK to PEM PKCS8
    const privateKey = createPrivateKey({ key: jwk as JsonWebKey, format: 'jwk' });
    const pem = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
    return pem;
  } catch (err) {
    throw new Error(
      `Invalid key format in ${fileName}: ${err instanceof Error ? err.message : String(err)}. ` +
        `Please ensure the key file contains a valid JWK.`
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
    const firstPass = JSON.parse(content) as unknown;
    if (typeof firstPass === 'string') {
      content = firstPass;
    } else if (Array.isArray(firstPass) && firstPass.every((entry) => typeof entry === 'string')) {
      content = firstPass
        .map((entry) =>
          entry.includes('-----BEGIN CERTIFICATE-----')
            ? entry
            : `-----BEGIN CERTIFICATE-----\n${entry}\n-----END CERTIFICATE-----`
        )
        .join('\n');
    }
  } catch {
    // Keep raw content when x5c file is plain PEM text.
  }

  try {
    const certificates = content.match(CERT_PEM_PATTERN) ?? [];
    if (certificates.length === 0) {
      throw new Error('no PEM certificates found');
    }

    for (const certPem of certificates) {
      new X509Certificate(certPem);
    }
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
    const { x5cCertPath, dataDir } = app.config;

    const [authRequestPrivateKeyPem, authResponsePrivateKeyPem, federationPrivateKeyPem, x5cCertPem] =
      await Promise.all([...KEY_FILES.map((kf) => loadKeyFile(dataDir, kf.file)), loadX5cCert(x5cCertPath)]);
    const signingPrivateKeyPem = authRequestPrivateKeyPem;

    app.decorate('rpKeys', {
      authRequestPrivateKeyPem,
      authResponsePrivateKeyPem,
      federationPrivateKeyPem,
      signingPrivateKeyPem,
      x5cCertPem
    });
  },
  { name: 'keys', dependencies: ['config'] }
);
