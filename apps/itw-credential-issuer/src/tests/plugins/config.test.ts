import Fastify from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import configPlugin from '../../plugins/config.js';

const ENV_KEYS = ['HOST', 'PORT', 'DATA_DIR', 'DB_CLEANUP_INTERVAL_MS', 'KEYS_DIR'] as const;

function cleanupEnv(): void {
  for (const key of ENV_KEYS) {
    delete process.env[key];
  }
}

describe('config plugin', () => {
  afterEach(() => {
    cleanupEnv();
  });

  it('loads default values when environment variables are not set', async () => {
    cleanupEnv();
    const app = Fastify();

    await app.register(configPlugin);
    await app.ready();

    expect(app.config.HOST).toBe('localhost');
    expect(app.config.PORT).toBe(3000);
    expect(app.config.DB_CLEANUP_INTERVAL_MS).toBe(60_000);
    expect(app.config.DATA_DIR.length).toBeGreaterThan(0);

    await app.close();
  });

  it('parses numeric values from environment variables', async () => {
    process.env.PORT = '4123';
    process.env.DB_CLEANUP_INTERVAL_MS = '1000';
    const app = Fastify();

    await app.register(configPlugin);
    await app.ready();

    expect(app.config.PORT).toBe(4123);
    expect(app.config.DB_CLEANUP_INTERVAL_MS).toBe(1000);

    await app.close();
  });
});
