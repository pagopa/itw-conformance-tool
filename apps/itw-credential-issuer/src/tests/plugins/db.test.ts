import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import Fastify from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import configPlugin from '../../plugins/config.js';
import dbPlugin from '../../plugins/db.js';

const ENV_KEYS = ['DATA_DIR', 'DB_CLEANUP_INTERVAL_MS', 'PORT', 'HOST', 'KEYS_DIR'] as const;

function cleanupEnv(): void {
  for (const key of ENV_KEYS) {
    delete process.env[key];
  }
}

describe('db plugin', () => {
  afterEach(() => {
    cleanupEnv();
  });

  it('registers sqlite client and repository implementations', async () => {
    const dataDir = mkdtempSync(path.join(tmpdir(), 'issuer-db-plugin-'));
    process.env.DATA_DIR = dataDir;
    process.env.DB_CLEANUP_INTERVAL_MS = '999999';

    const app = Fastify();
    await app.register(configPlugin);
    await app.register(dbPlugin);
    await app.ready();

    expect(app.dbClient).toBeDefined();
    expect(app.nonceRepository).toBeDefined();
    expect(app.parRepository).toBeDefined();
    expect(app.sessionRepository).toBeDefined();

    await app.nonceRepository.insert('nonce-value', Date.now() + 60_000);
    const value = await app.nonceRepository.get('nonce-value');
    expect(value).toBe('nonce-value');

    await app.close();
  });
});
