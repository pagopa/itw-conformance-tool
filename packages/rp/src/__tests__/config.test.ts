import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  DEFAULT_DATA_DIR,
  DEFAULT_HOST,
  DEFAULT_PORT,
  deriveBaseUrl,
  loadRpConfig,
  rpConfigSchema
} from '../config.js';

describe('deriveBaseUrl', () => {
  it('uses localhost when host is 0.0.0.0', () => {
    expect(deriveBaseUrl({ host: '0.0.0.0', port: 8080 })).toBe('http://localhost:8080');
  });

  it('uses the configured host otherwise', () => {
    expect(deriveBaseUrl({ host: 'rp.example.com', port: 8080 })).toBe('http://rp.example.com:8080');
  });
});

describe('rpConfigSchema', () => {
  it('accepts a valid config', () => {
    const parsed = rpConfigSchema.safeParse({
      host: '0.0.0.0',
      port: 8080,
      baseUrl: 'http://localhost:8080',
      entityId: 'http://localhost:8080',
      trustAnchorUrl: 'https://trust-anchor.example.org/.well-known/openid-federation',
      dataDir: '/tmp/itw',
      configFilePath: '/tmp/config.ini'
    });
    expect(parsed.success).toBe(true);
  });

  it('rejects out-of-range ports', () => {
    const parsed = rpConfigSchema.safeParse({
      host: '0.0.0.0',
      port: 99999,
      baseUrl: 'http://localhost:99999',
      dataDir: '/tmp',
      configFilePath: '/tmp/c.ini'
    });
    expect(parsed.success).toBe(false);
  });
});

describe('loadRpConfig', () => {
  let workDir: string;

  beforeEach(() => {
    workDir = mkdtempSync(join(tmpdir(), 'itw-rp-config-'));
  });

  afterEach(() => {
    rmSync(workDir, { recursive: true, force: true });
  });

  it('returns defaults when no config file exists', () => {
    const result = loadRpConfig({
      configFilePath: join(workDir, 'missing.ini'),
      env: {}
    });

    expect(result.configFileFound).toBe(false);
    expect(result.config.host).toBe(DEFAULT_HOST);
    expect(result.config.port).toBe(DEFAULT_PORT);
    expect(result.config.dataDir).toBe(DEFAULT_DATA_DIR);
    expect(result.config.baseUrl).toBe(`http://localhost:${DEFAULT_PORT}`);
    expect(result.config.entityId).toBe(`http://localhost:${DEFAULT_PORT}`);
  });

  it('reads [rp].port and [global].data_dir from the ini file', () => {
    const cfgPath = join(workDir, 'config.ini');
    writeFileSync(
      cfgPath,
      '[global]\ndata_dir = /opt/itw-data\n\n[rp]\nentity_id = https://rp.example.org\nport = 9090\ntrust_anchor = https://trust-anchor.example.org/.well-known/openid-federation\n'
    );

    const result = loadRpConfig({ configFilePath: cfgPath, env: {} });

    expect(result.configFileFound).toBe(true);
    expect(result.config.port).toBe(9090);
    expect(result.config.dataDir).toBe('/opt/itw-data');
    expect(result.config.baseUrl).toBe('http://localhost:9090');
    expect(result.config.entityId).toBe('https://rp.example.org');
    expect(result.config.trustAnchorUrl).toBe('https://trust-anchor.example.org/.well-known/openid-federation');
    expect(result.config.configFilePath).toBe(cfgPath);
  });

  it('env override ITW_CT_RP_ENTITY_ID wins over the ini file', () => {
    const cfgPath = join(workDir, 'config.ini');
    writeFileSync(cfgPath, '[rp]\nentity_id = https://rp-from-ini.example.org\n');

    const result = loadRpConfig({
      configFilePath: cfgPath,
      env: { ITW_CT_RP_ENTITY_ID: 'https://rp-from-env.example.org' }
    });

    expect(result.config.entityId).toBe('https://rp-from-env.example.org');
  });

  it('env override ITW_CT_RP_TRUST_ANCHOR_URL wins over the ini file', () => {
    const cfgPath = join(workDir, 'config.ini');
    writeFileSync(cfgPath, '[rp]\ntrust_anchor = https://ta-from-ini.example.org/.well-known/openid-federation\n');

    const result = loadRpConfig({
      configFilePath: cfgPath,
      env: { ITW_CT_RP_TRUST_ANCHOR_URL: 'https://ta-from-env.example.org/.well-known/openid-federation' }
    });

    expect(result.config.trustAnchorUrl).toBe('https://ta-from-env.example.org/.well-known/openid-federation');
  });

  it('env override ITW_CT_RP_PORT wins over the ini file', () => {
    const cfgPath = join(workDir, 'config.ini');
    writeFileSync(cfgPath, '[rp]\nport = 9090\n');

    const result = loadRpConfig({
      configFilePath: cfgPath,
      env: { ITW_CT_RP_PORT: '12345' }
    });

    expect(result.config.port).toBe(12345);
  });

  it('env override ITW_CT_DATA_DIR wins over the ini file', () => {
    const cfgPath = join(workDir, 'config.ini');
    writeFileSync(cfgPath, '[global]\ndata_dir = /from/ini\n');

    const result = loadRpConfig({
      configFilePath: cfgPath,
      env: { ITW_CT_DATA_DIR: '/from/env' }
    });

    expect(result.config.dataDir).toBe('/from/env');
  });

  it('invalid [rp].port in the ini file falls back to the default port', () => {
    const cfgPath = join(workDir, 'config.ini');
    writeFileSync(cfgPath, '[rp]\nport = 99999\n');

    const result = loadRpConfig({ configFilePath: cfgPath, env: {} });

    expect(result.config.port).toBe(DEFAULT_PORT);
  });

  it('rejects an invalid port in the env override', () => {
    expect(() =>
      loadRpConfig({
        configFilePath: join(workDir, 'missing.ini'),
        env: { ITW_CT_RP_PORT: 'not-a-port' }
      })
    ).toThrow(/Invalid ITW_CT_RP_PORT/);
  });

  it('env override ITW_CT_RP_BASE_URL wins over the derived baseUrl', () => {
    const result = loadRpConfig({
      configFilePath: join(workDir, 'missing.ini'),
      env: { ITW_CT_RP_BASE_URL: 'http://rp.example.com:9000' }
    });

    expect(result.config.baseUrl).toBe('http://rp.example.com:9000');
  });

  it('empty ITW_CT_RP_BASE_URL falls back to derived baseUrl', () => {
    const result = loadRpConfig({
      configFilePath: join(workDir, 'missing.ini'),
      env: { ITW_CT_RP_BASE_URL: '' }
    });

    expect(result.config.baseUrl).toBe(`http://localhost:${DEFAULT_PORT}`);
  });

  it('whitespace-only ITW_CT_RP_BASE_URL falls back to derived baseUrl', () => {
    const result = loadRpConfig({
      configFilePath: join(workDir, 'missing.ini'),
      env: { ITW_CT_RP_BASE_URL: '   ' }
    });

    expect(result.config.baseUrl).toBe(`http://localhost:${DEFAULT_PORT}`);
  });

  it('ITW_CT_RP_BASE_URL trailing slash is stripped by Zod URL normalization', () => {
    // Zod's z.string().url() uses WHATWG URL semantics which strips the trailing
    // slash from the root path (http://host:port/ → http://host:port).
    const result = loadRpConfig({
      configFilePath: join(workDir, 'missing.ini'),
      env: { ITW_CT_RP_BASE_URL: 'http://rp.example.com:9000/' }
    });

    expect(result.config.baseUrl).toBe('http://rp.example.com:9000');
  });
});
