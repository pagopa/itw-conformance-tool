import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import Fastify from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import configPlugin from '../../plugins/config.js';
import keysPlugin from '../../plugins/keys.js';

const ENV_KEYS = ['DATA_DIR', 'PORT', 'HOST', 'DB_CLEANUP_INTERVAL_MS', 'ITW_CT_DATA_DIR'] as const;

function cleanupEnv(): void {
  for (const key of ENV_KEYS) {
    delete process.env[key];
  }
}

/** Creates a temp root dir and an `issuer` subdir inside it.
 * Pass `rootDir` as `DATA_DIR` so the plugin resolves `path.join(DATA_DIR, 'issuer')` to `issuerDir`. */
function createIssuerDir(): { rootDir: string; issuerDir: string } {
  const rootDir = mkdtempSync(path.join(tmpdir(), 'issuer-keys-plugin-'));
  const issuerDir = path.join(rootDir, 'issuer');
  mkdirSync(issuerDir);
  return { rootDir, issuerDir };
}

function writePemFiles(dir: string): void {
  writeFileSync(path.join(dir, 'iaca-cert.pem'), '-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n');
  writeFileSync(path.join(dir, 'iaca-key.pem'), '-----BEGIN PRIVATE KEY-----\nTEST\n-----END PRIVATE KEY-----\n');
}

describe('keys plugin', () => {
  afterEach(() => {
    cleanupEnv();
  });

  it('loads existing key files into fastify instance', async () => {
    const { rootDir, issuerDir } = createIssuerDir();
    writeFileSync(path.join(issuerDir, 'signing-keys.jwks.json'), JSON.stringify({ keys: [{ kid: 'test-kid' }] }));
    writePemFiles(issuerDir);
    process.env.DATA_DIR = rootDir;

    const app = Fastify();
    await app.register(configPlugin);
    await app.register(keysPlugin);
    await app.ready();

    const jwks = JSON.parse(app.issuerKeys.signingKeysJwks);
    expect(jwks.keys).toHaveLength(1);
    expect(app.issuerKeys.iacaCertPem).toContain('BEGIN CERTIFICATE');
    expect(app.issuerKeys.iacaKeyPem).toContain('BEGIN PRIVATE KEY');

    await app.close();
  });

  it('auto-generates all key material when the issuer directory is empty', async () => {
    const { rootDir, issuerDir } = createIssuerDir();
    process.env.DATA_DIR = rootDir;

    const app = Fastify();
    await app.register(configPlugin);
    await app.register(keysPlugin);
    await app.ready();

    expect(existsSync(path.join(issuerDir, 'signing-keys.jwks.json'))).toBe(true);
    expect(existsSync(path.join(issuerDir, 'iaca-cert.pem'))).toBe(true);
    expect(existsSync(path.join(issuerDir, 'iaca-key.pem'))).toBe(true);

    const jwks = JSON.parse(app.issuerKeys.signingKeysJwks);
    expect(Array.isArray(jwks.keys)).toBe(true);
    expect(jwks.keys.length).toBeGreaterThanOrEqual(1);
    expect(app.issuerKeys.iacaCertPem).toContain('BEGIN CERTIFICATE');
    expect(app.issuerKeys.iacaKeyPem).toContain('BEGIN PRIVATE KEY');

    await app.close();
  });

  it('auto-generates IACA files when only the JWKS exists', async () => {
    const { rootDir, issuerDir } = createIssuerDir();
    writeFileSync(path.join(issuerDir, 'signing-keys.jwks.json'), JSON.stringify({ keys: [{ kid: 'existing-kid' }] }));
    process.env.DATA_DIR = rootDir;

    const app = Fastify();
    await app.register(configPlugin);
    await app.register(keysPlugin);
    await app.ready();

    expect(existsSync(path.join(issuerDir, 'iaca-cert.pem'))).toBe(true);
    expect(existsSync(path.join(issuerDir, 'iaca-key.pem'))).toBe(true);
    // Pre-existing JWKS is preserved unchanged
    const jwks = JSON.parse(app.issuerKeys.signingKeysJwks);
    expect(jwks.keys[0].kid).toBe('existing-kid');

    await app.close();
  });

  it('auto-generates the JWKS when only IACA files exist', async () => {
    const { rootDir, issuerDir } = createIssuerDir();
    writePemFiles(issuerDir);
    process.env.DATA_DIR = rootDir;

    const app = Fastify();
    await app.register(configPlugin);
    await app.register(keysPlugin);
    await app.ready();

    expect(existsSync(path.join(issuerDir, 'signing-keys.jwks.json'))).toBe(true);
    const jwks = JSON.parse(app.issuerKeys.signingKeysJwks);
    expect(Array.isArray(jwks.keys)).toBe(true);

    await app.close();
  });

  it('throws when the keys directory does not exist', async () => {
    const rootDir = mkdtempSync(path.join(tmpdir(), 'issuer-keys-plugin-no-dir-'));
    // DATA_DIR = rootDir  →  keysDir = rootDir/issuer  (not created)
    process.env.DATA_DIR = rootDir;

    const app = Fastify();
    await app.register(configPlugin);
    await expect(app.register(keysPlugin)).rejects.toThrow('Issuer directory does not exist');
  });
});
