import { existsSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import Fastify from 'fastify';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';

import { generateIaca, generateJwks } from '../../crypto/auto-keygen.js';
import configPlugin from '../../plugins/config.js';
import keysPlugin from '../../plugins/keys.js';

const ENV_KEYS = ['DATA_DIR', 'cPORT', 'HOST', 'DB_CLEANUP_INTERVAL_MS', 'ITW_CT_DATA_DIR'] as const;

function cleanupEnv(): void {
  for (const key of ENV_KEYS) {
    delete process.env[key];
  }
}

/** Real key material generated once for all tests that need pre-existing files. */
let realIaca: { certPem: string; keyPem: string };
let realJwksJson: string;

beforeAll(async () => {
  [realIaca, realJwksJson] = await Promise.all([generateIaca(), generateJwks()]);
});

/** Creates a temp root dir and an `issuer` subdir inside it.
 * Pass `rootDir` as `DATA_DIR` so the plugin resolves `path.join(DATA_DIR, 'issuer')` to `issuerDir`. */
function createIssuerDir(): { rootDir: string; issuerDir: string } {
  const rootDir = mkdtempSync(path.join(tmpdir(), 'issuer-keys-plugin-'));
  const issuerDir = path.join(rootDir, 'issuer');
  mkdirSync(issuerDir);
  return { rootDir, issuerDir };
}

/** Writes real IACA cert + key PEM files into `dir`. */
function writePemFiles(dir: string): void {
  writeFileSync(path.join(dir, 'iaca-cert.pem'), realIaca.certPem);
  writeFileSync(path.join(dir, 'iaca-key.pem'), realIaca.keyPem);
}

describe('keys plugin', () => {
  afterEach(() => {
    cleanupEnv();
  });

  it('loads existing key files into fastify instance', async () => {
    const { rootDir, issuerDir } = createIssuerDir();
    writeFileSync(path.join(issuerDir, 'signing-keys.jwks.json'), realJwksJson);
    writePemFiles(issuerDir);
    process.env.DATA_DIR = rootDir;

    const app = Fastify();
    await app.register(configPlugin);
    await app.register(keysPlugin);
    await app.ready();

    expect(app.issuerKeys.signingKeysJwks.keys.length).toBeGreaterThanOrEqual(1);
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

    expect(Array.isArray(app.issuerKeys.signingKeysJwks.keys)).toBe(true);
    expect(app.issuerKeys.signingKeysJwks.keys.length).toBeGreaterThanOrEqual(1);
    expect(app.issuerKeys.iacaCertPem).toContain('BEGIN CERTIFICATE');
    expect(app.issuerKeys.iacaKeyPem).toContain('BEGIN PRIVATE KEY');

    await app.close();
  });

  it('auto-generates IACA files when only the JWKS exists', async () => {
    const { rootDir, issuerDir } = createIssuerDir();
    writeFileSync(path.join(issuerDir, 'signing-keys.jwks.json'), realJwksJson);
    process.env.DATA_DIR = rootDir;

    const app = Fastify();
    await app.register(configPlugin);
    await app.register(keysPlugin);
    await app.ready();

    expect(existsSync(path.join(issuerDir, 'iaca-cert.pem'))).toBe(true);
    expect(existsSync(path.join(issuerDir, 'iaca-key.pem'))).toBe(true);
    // Pre-existing JWKS is preserved — same number of keys
    expect(app.issuerKeys.signingKeysJwks.keys.length).toBe(JSON.parse(realJwksJson).keys.length);

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
    expect(Array.isArray(app.issuerKeys.signingKeysJwks.keys)).toBe(true);

    await app.close();
  });

  it('regenerates JWKS when existing file contains only RSA / incompatible keys', async () => {
    const { rootDir, issuerDir } = createIssuerDir();
    // Write an RSA-only JWKS (no EC sig key, no ECDH-ES enc key)
    const incompatibleJwks = JSON.stringify({
      keys: [
        {
          kty: 'RSA',
          kid: 'rsa-key',
          use: 'sig',
          alg: 'RS256',
          n: 'sHfHFq1234',
          e: 'AQAB'
        }
      ]
    });
    writeFileSync(path.join(issuerDir, 'signing-keys.jwks.json'), incompatibleJwks);
    writePemFiles(issuerDir);
    process.env.DATA_DIR = rootDir;

    const app = Fastify();
    await app.register(configPlugin);
    await app.register(keysPlugin);
    await app.ready();

    // Plugin must have replaced the file with compatible EC keys
    const regenerated = app.issuerKeys.signingKeysJwks;
    type AnyJwk = (typeof regenerated.keys)[number] & { use?: string };
    const ecSigKey = (regenerated.keys as AnyJwk[]).find(
      (k) => k.kty === 'EC' && (k.use === 'sig' || k.use === undefined)
    );
    const ecEncKey = (regenerated.keys as AnyJwk[]).find((k) => k.kty === 'EC' && k.use === 'enc');
    expect(ecSigKey).toBeDefined();
    expect(ecEncKey).toBeDefined();

    await app.close();
  });

  it('throws when the keys directory does not exist', async () => {
    const rootDir = mkdtempSync(path.join(tmpdir(), 'issuer-keys-plugin-no-dir-'));
    // DATA_DIR = rootDir  →  keysDir = rootDir/issuer  (not created)
    process.env.DATA_DIR = rootDir;

    const app = Fastify();
    await app.register(configPlugin);
    await expect(app.register(keysPlugin)).rejects.toThrow();
  });
});
