import { tmpdir } from 'node:os';
import path from 'node:path';

import Fastify from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import configPlugin from '../../plugins/config.js';

const ENV_KEYS = [
  'BASE_URL_SCHEME',
  'HOST',
  'PORT',
  'DATA_DIR',
  'DB_CLEANUP_INTERVAL_MS',
  'KEYS_DIR',
  'AUTH_FLOW',
  'ITW_CT_DATA_DIR',
  'ITW_CT_ISSUER_PORT',
  'ITW_CT_ISSUER_AUTH_FLOW'
] as const;

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

    expect(app.config.BASE_URL_SCHEME).toBe('http');
    expect(app.config.HOST).toBe('localhost');
    expect(app.config.PORT).toBe(3000);
    expect(app.config.DB_CLEANUP_INTERVAL_MS).toBe(60_000);
    expect(app.config.DATA_DIR.length).toBeGreaterThan(0);
    expect(app.config.AUTH_FLOW).toBe('direct');

    await app.close();
  });

  it('parses numeric values from environment variables', async () => {
    process.env.BASE_URL_SCHEME = 'http';
    process.env.PORT = '4123';
    process.env.DB_CLEANUP_INTERVAL_MS = '1000';
    const app = Fastify();

    await app.register(configPlugin);
    await app.ready();

    expect(app.config.BASE_URL_SCHEME).toBe('http');
    expect(app.config.PORT).toBe(4123);
    expect(app.config.DB_CLEANUP_INTERVAL_MS).toBe(1000);

    await app.close();
  });

  it('uses ITW_CT_ISSUER_PORT as override for PORT', async () => {
    process.env.PORT = '4123';
    process.env.ITW_CT_ISSUER_PORT = '5010';
    const app = Fastify();

    await app.register(configPlugin);
    await app.ready();

    expect(app.config.PORT).toBe(5010);

    await app.close();
  });

  it('uses ITW_CT_DATA_DIR as base directory for DATA_DIR', async () => {
    process.env.ITW_CT_DATA_DIR = path.join(tmpdir(), 'itw-conformance-tool');
    const app = Fastify();

    await app.register(configPlugin);
    await app.ready();

    expect(app.config.DATA_DIR).toBe(path.join(tmpdir(), 'itw-conformance-tool'));

    await app.close();
  });

  it('throws when ITW_CT_ISSUER_PORT is invalid', async () => {
    process.env.ITW_CT_ISSUER_PORT = '0';
    const app = Fastify();

    await expect(app.register(configPlugin)).rejects.toThrow('Invalid ITW_CT_ISSUER_PORT value: 0');
  });

  it('throws when PORT is out of valid TCP range', async () => {
    process.env.PORT = '70000';
    const app = Fastify();

    await expect(app.register(configPlugin)).rejects.toThrow();
  });

  it('uses ITW_CT_ISSUER_AUTH_FLOW as override for AUTH_FLOW', async () => {
    process.env.ITW_CT_ISSUER_AUTH_FLOW = 'l3';
    const app = Fastify();

    await app.register(configPlugin);
    await app.ready();

    expect(app.config.AUTH_FLOW).toBe('l3');

    await app.close();
  });

  it('accepts all valid auth_flow values', async () => {
    for (const flow of ['direct', 'l2plus', 'l3'] as const) {
      process.env.ITW_CT_ISSUER_AUTH_FLOW = flow;
      const app = Fastify();

      await app.register(configPlugin);
      await app.ready();

      expect(app.config.AUTH_FLOW).toBe(flow);

      await app.close();
      cleanupEnv();
    }
  });

  it('throws when ITW_CT_ISSUER_AUTH_FLOW is invalid', async () => {
    process.env.ITW_CT_ISSUER_AUTH_FLOW = 'unknown';
    const app = Fastify();

    await expect(app.register(configPlugin)).rejects.toThrow(
      'env/AUTH_FLOW must be equal to one of the allowed values'
    );
  });
});
