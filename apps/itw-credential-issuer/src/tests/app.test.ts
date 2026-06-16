import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { generateJWKS, getIACAChain } from '@itw-conformance-tool/crypto';
import Fastify from 'fastify';
import fp from 'fastify-plugin';
import { afterEach, describe, expect, it } from 'vitest';

import bootstrap from '../app.js';

const ENV_KEYS = ['DATA_DIR', 'PORT', 'HOST', 'DB_CLEANUP_INTERVAL_MS'] as const;

function cleanupEnv(): void {
  for (const key of ENV_KEYS) {
    delete process.env[key];
  }
}

async function setupKeyMaterial(): Promise<string> {
  const rootDir = mkdtempSync(path.join(tmpdir(), 'issuer-app-keys-'));
  const issuerDir = path.join(rootDir, 'issuer');
  mkdirSync(issuerDir);
  const [jwksJson, iaca] = await Promise.all([
    generateJWKS({
      keys: [
        { alg: 'ES256', use: 'sig', count: 1, keyOps: ['sign'] },
        { alg: 'ECDH-ES', use: 'enc', count: 1, keyOps: ['deriveKey'] }
      ]
    }),
    getIACAChain()
  ]);
  writeFileSync(path.join(issuerDir, 'signing-keys.jwks.json'), JSON.stringify(jwksJson));
  writeFileSync(path.join(issuerDir, 'iaca-cert.pem'), iaca.certificate);
  writeFileSync(path.join(issuerDir, 'iaca-key.pem'), iaca.privateKey);

  return rootDir;
}

describe('issuer app bootstrap', () => {
  afterEach(() => {
    cleanupEnv();
  });

  it('registers plugins and serves health route', async () => {
    process.env.DATA_DIR = await setupKeyMaterial();
    process.env.DB_CLEANUP_INTERVAL_MS = '999999';

    const app = Fastify();
    await app.register(fp(bootstrap));
    await app.ready();

    const response = await app.inject({ method: 'GET', url: '/health' });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ status: 'ok' });
    expect(app.config.PORT).toBe(3000);
    expect(app.dbClient).toBeDefined();
    expect(app.issuerKeys.signingKeysJwks.keys).toHaveLength(2);

    await app.close();
  });

  it('returns 404 for missing routes', async () => {
    process.env.DATA_DIR = await setupKeyMaterial();

    const app = Fastify();
    await app.register(fp(bootstrap));
    await app.ready();

    const response = await app.inject({ method: 'GET', url: '/missing' });

    expect(response.statusCode).toBe(404);
    expect(response.json()).toEqual({ message: 'Not Found' });

    await app.close();
  });
});
