import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import Fastify from 'fastify';
import fp from 'fastify-plugin';
import { afterEach, describe, expect, it } from 'vitest';

import bootstrap from '../app.js';

const ENV_KEYS = ['KEYS_DIR', 'DATA_DIR', 'PORT', 'HOST', 'DB_CLEANUP_INTERVAL_MS'] as const;

function cleanupEnv(): void {
  for (const key of ENV_KEYS) {
    delete process.env[key];
  }
}

function setupKeyMaterial(): string {
  const keysDir = mkdtempSync(path.join(tmpdir(), 'issuer-app-keys-'));
  writeFileSync(path.join(keysDir, 'signing-keys.jwks.json'), JSON.stringify({ keys: [{ kid: 'issuer-kid' }] }));
  writeFileSync(path.join(keysDir, 'iaca-cert.pem'), '-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----\n');
  writeFileSync(path.join(keysDir, 'iaca-key.pem'), '-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n');

  return keysDir;
}

describe('issuer app bootstrap', () => {
  afterEach(() => {
    cleanupEnv();
  });

  it('registers plugins and serves health route', async () => {
    process.env.KEYS_DIR = setupKeyMaterial();
    process.env.DATA_DIR = mkdtempSync(path.join(tmpdir(), 'issuer-app-db-'));
    process.env.DB_CLEANUP_INTERVAL_MS = '999999';

    const app = Fastify();
    await app.register(fp(bootstrap));
    await app.ready();

    const response = await app.inject({ method: 'GET', url: '/health' });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ status: 'ok' });
    expect(app.config.PORT).toBe(3000);
    expect(app.dbClient).toBeDefined();
    expect(app.issuerKeys.signingKeysJwks.keys).toHaveLength(1);

    await app.close();
  });

  it('returns 404 for missing routes', async () => {
    process.env.KEYS_DIR = setupKeyMaterial();
    process.env.DATA_DIR = mkdtempSync(path.join(tmpdir(), 'issuer-app-db-missing-route-'));

    const app = Fastify();
    await app.register(fp(bootstrap));
    await app.ready();

    const response = await app.inject({ method: 'GET', url: '/missing' });

    expect(response.statusCode).toBe(404);
    expect(response.json()).toEqual({ message: 'Not Found' });

    await app.close();
  });
});
