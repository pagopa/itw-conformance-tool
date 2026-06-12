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
  'HTTPS_ENABLED',
  'TLS_CERT_PATH',
  'TLS_KEY_PATH',
  'ITW_CT_DATA_DIR',
  'ITW_CT_ISSUER_PORT',
  'ITW_CT_ISSUER_AUTH_FLOW',
  'ITW_CT_HTTPS',
  'ITW_CT_TLS_CERT_PATH',
  'ITW_CT_TLS_KEY_PATH'
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
    expect(app.config.HOST).toBe('127.0.0.1');
    expect(app.config.PORT).toBe(3000);
    expect(app.config.DB_CLEANUP_INTERVAL_MS).toBe(60_000);
    expect(app.config.DATA_DIR.length).toBeGreaterThan(0);
    expect(app.config.AUTH_FLOW).toBe('direct');
    expect(app.config.HTTPS_ENABLED).toBe(true);

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

  it('defaults HTTPS_ENABLED to true and TLS paths to empty strings', async () => {
    cleanupEnv();
    const app = Fastify();

    await app.register(configPlugin);
    await app.ready();

    expect(app.config.HTTPS_ENABLED).toBe(true);
    expect(app.config.TLS_CERT_PATH).toBe('');
    expect(app.config.TLS_KEY_PATH).toBe('');

    await app.close();
  });

  it('parses ITW_CT_HTTPS=true and sets BASE_URL_SCHEME to https when not explicitly set', async () => {
    process.env.ITW_CT_HTTPS = 'true';
    const app = Fastify();

    await app.register(configPlugin);
    await app.ready();

    expect(app.config.HTTPS_ENABLED).toBe(true);
    expect(app.config.BASE_URL_SCHEME).toBe('https');

    await app.close();
  });

  it('does not override BASE_URL_SCHEME when explicitly set even if HTTPS is enabled', async () => {
    process.env.ITW_CT_HTTPS = 'true';
    process.env.BASE_URL_SCHEME = 'http';
    const app = Fastify();

    await app.register(configPlugin);
    await app.ready();

    expect(app.config.BASE_URL_SCHEME).toBe('http');

    await app.close();
  });

  it('maps ITW_CT_TLS_CERT_PATH and ITW_CT_TLS_KEY_PATH into config', async () => {
    process.env.ITW_CT_TLS_CERT_PATH = '/etc/ssl/cert.pem';
    process.env.ITW_CT_TLS_KEY_PATH = '/etc/ssl/key.pem';
    const app = Fastify();

    await app.register(configPlugin);
    await app.ready();

    expect(app.config.TLS_CERT_PATH).toBe('/etc/ssl/cert.pem');
    expect(app.config.TLS_KEY_PATH).toBe('/etc/ssl/key.pem');

    await app.close();
  });

  it('does not enable HTTPS for unexpected values like FALSE or no', async () => {
    for (const value of ['FALSE', 'No', 'off']) {
      process.env.ITW_CT_HTTPS = value;
      const app = Fastify();

      await app.register(configPlugin);
      await app.ready();

      expect(app.config.HTTPS_ENABLED).toBe(false);

      await app.close();
      cleanupEnv();
    }
  });
});
