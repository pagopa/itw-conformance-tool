import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import Fastify from 'fastify';
import fp from 'fastify-plugin';

import bootstrap from '../../app.js';

const ENV_KEYS = ['DATA_DIR', 'PORT', 'HOST', 'DB_CLEANUP_INTERVAL_MS'] as const;

function cleanupEnv(): void {
  for (const key of ENV_KEYS) {
    delete process.env[key];
  }
}

function setupKeyMaterial(): string {
  const rootDir = mkdtempSync(path.join(tmpdir(), 'issuer-routes-'));
  const issuerDir = path.join(rootDir, 'issuer');
  mkdirSync(issuerDir);
  writeFileSync(
    path.join(issuerDir, 'signing-keys.jwks.json'),
    JSON.stringify({
      keys: [
        {
          alg: 'ES256',
          crv: 'P-256',
          d: 'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY',
          kid: 'issuer-sign-key',
          kty: 'EC',
          x: 'f83OJ3D2xF4x6xw5vM90oCbGyF_F7fsRG3Gzdh0dX8Q',
          y: 'x_FEzRu9h4M5xYfZfbQ3VIAtF_forNCz7L3A5kZZgU8'
        }
      ]
    })
  );
  writeFileSync(
    path.join(issuerDir, 'iaca-cert.pem'),
    '-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----\n'
  );
  writeFileSync(path.join(issuerDir, 'iaca-key.pem'), '-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n');

  return rootDir;
}

export async function createIssuerApp() {
  cleanupEnv();

  process.env.DATA_DIR = setupKeyMaterial();
  process.env.DB_CLEANUP_INTERVAL_MS = '999999';

  const app = Fastify();
  await app.register(fp(bootstrap));
  await app.ready();

  return app;
}

export async function closeIssuerApp(app: Awaited<ReturnType<typeof createIssuerApp>>) {
  await app.close();
  cleanupEnv();
}
