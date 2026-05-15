import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import Fastify from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import configPlugin from '../../plugins/config.js';
import keysPlugin from '../../plugins/keys.js';

const ENV_KEYS = ['KEYS_DIR', 'PORT', 'HOST', 'DATA_DIR', 'DB_CLEANUP_INTERVAL_MS'] as const;

function cleanupEnv(): void {
  for (const key of ENV_KEYS) {
    delete process.env[key];
  }
}

describe('keys plugin', () => {
  afterEach(() => {
    cleanupEnv();
  });

  function writePemFiles(keysDir: string): void {
    writeFileSync(
      path.join(keysDir, 'iaca-cert.pem'),
      '-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n'
    );
    writeFileSync(path.join(keysDir, 'iaca-key.pem'), '-----BEGIN PRIVATE KEY-----\nTEST\n-----END PRIVATE KEY-----\n');
  }

  it('loads jwks and pem files into fastify instance', async () => {
    const keysDir = mkdtempSync(path.join(tmpdir(), 'issuer-keys-plugin-'));
    writeFileSync(path.join(keysDir, 'signing-keys.jwks.json'), JSON.stringify({ keys: [{ kid: 'test-kid' }] }));
    writePemFiles(keysDir);
    process.env.KEYS_DIR = keysDir;

    const app = Fastify();
    await app.register(configPlugin);
    await app.register(keysPlugin);
    await app.ready();

    expect(app.issuerKeys.signingKeysJwks.keys).toHaveLength(1);
    expect(app.issuerKeys.iacaCertPem).toContain('BEGIN CERTIFICATE');
    expect(app.issuerKeys.iacaKeyPem).toContain('BEGIN PRIVATE KEY');

    await app.close();
  });

  it('fails with a clear error when required files are missing', async () => {
    const keysDir = mkdtempSync(path.join(tmpdir(), 'issuer-keys-plugin-missing-'));
    writeFileSync(path.join(keysDir, 'signing-keys.jwks.json'), JSON.stringify({ keys: [] }));
    process.env.KEYS_DIR = keysDir;

    const app = Fastify();
    await app.register(configPlugin);

    await expect(app.register(keysPlugin)).rejects.toThrow('Required key material file is missing or not readable:');
  });

  it('fails with a clear error when signing-keys.jwks.json is not valid JSON', async () => {
    const keysDir = mkdtempSync(path.join(tmpdir(), 'issuer-keys-plugin-invalid-json-'));
    writeFileSync(path.join(keysDir, 'signing-keys.jwks.json'), '{ not-valid-json');
    writePemFiles(keysDir);
    process.env.KEYS_DIR = keysDir;

    const app = Fastify();
    await app.register(configPlugin);

    await expect(app.register(keysPlugin)).rejects.toThrow('Invalid JSON in');
  });

  it('fails when signing-keys.jwks.json does not contain a keys array', async () => {
    const keysDir = mkdtempSync(path.join(tmpdir(), 'issuer-keys-plugin-invalid-jwks-'));
    writeFileSync(path.join(keysDir, 'signing-keys.jwks.json'), JSON.stringify({ foo: 'bar' }));
    writePemFiles(keysDir);
    process.env.KEYS_DIR = keysDir;

    const app = Fastify();
    await app.register(configPlugin);

    await expect(app.register(keysPlugin)).rejects.toThrow('expected an object with a keys array');
  });
});
