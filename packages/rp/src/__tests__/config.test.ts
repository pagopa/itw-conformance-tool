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
  resolveHttpsEnabled,
  resolveTlsPaths,
  rpConfigSchema
} from '../config.js';

const REQUIRED_FIELDS_ENV = {
  ITW_CT_RP_TRUST_ANCHOR_URL: 'https://trust-anchor.example.com',
  ITW_CT_RP_X5C_CERT_PATH: '/tmp/x5c-cert.pem'
};

const REQUIRED_FIELDS_INI = `
[rp]
trust_anchor_url = https://trust-anchor.example.com
x5c_cert_path = /tmp/x5c-cert.pem
`;

describe('deriveBaseUrl', () => {
  it('uses localhost when host is 0.0.0.0', () => {
    expect(deriveBaseUrl({ host: '0.0.0.0', port: 8080 })).toBe('http://localhost:8080');
  });

  it('uses the configured host otherwise', () => {
    expect(deriveBaseUrl({ host: 'rp.example.com', port: 8080 })).toBe('http://rp.example.com:8080');
  });

  it('uses https scheme when scheme is https', () => {
    expect(deriveBaseUrl({ host: '0.0.0.0', port: 8443, scheme: 'https' })).toBe('https://localhost:8443');
  });

  it('defaults to http when scheme is omitted', () => {
    expect(deriveBaseUrl({ host: 'rp.example.com', port: 8080 })).toBe('http://rp.example.com:8080');
  });
});

describe('resolveHttpsEnabled', () => {
  it('uses the fallback when ITW_CT_HTTPS is not set', () => {
    expect(resolveHttpsEnabled({}, true)).toBe(true);
    expect(resolveHttpsEnabled({}, false)).toBe(false);
  });

  it('accepts true-like values from env', () => {
    expect(resolveHttpsEnabled({ ITW_CT_HTTPS: 'true' }, false)).toBe(true);
    expect(resolveHttpsEnabled({ ITW_CT_HTTPS: '1' }, false)).toBe(true);
  });

  it('treats other env values as disabled', () => {
    expect(resolveHttpsEnabled({ ITW_CT_HTTPS: 'false' }, true)).toBe(false);
    expect(resolveHttpsEnabled({ ITW_CT_HTTPS: 'no' }, true)).toBe(false);
  });
});

describe('resolveTlsPaths', () => {
  it('derives TLS paths from dataDir when env overrides are not set', () => {
    const result = resolveTlsPaths({ dataDir: '/tmp/itw', env: {} });

    expect(result.certPath).toBe('/tmp/itw/tls-cert.pem');
    expect(result.keyPath).toBe('/tmp/itw/tls-key.pem');
  });

  it('uses explicit env overrides when provided', () => {
    const result = resolveTlsPaths({
      dataDir: '/tmp/itw',
      env: {
        ITW_CT_TLS_CERT_PATH: '/certs/server.pem',
        ITW_CT_TLS_KEY_PATH: '/keys/server-key.pem'
      }
    });

    expect(result.certPath).toBe('/certs/server.pem');
    expect(result.keyPath).toBe('/keys/server-key.pem');
  });

  it('expands ~ in ITW_CT_TLS_CERT_PATH and ITW_CT_TLS_KEY_PATH', () => {
    const result = resolveTlsPaths({
      dataDir: '/tmp/itw',
      env: {
        ITW_CT_TLS_CERT_PATH: '~/certs/cert.pem',
        ITW_CT_TLS_KEY_PATH: '~/certs/key.pem'
      }
    });

    expect(result.certPath).not.toContain('~');
    expect(result.certPath).toContain('certs/cert.pem');
    expect(result.keyPath).not.toContain('~');
    expect(result.keyPath).toContain('certs/key.pem');
  });
});

describe('rpConfigSchema', () => {
  const BASE_VALID = {
    host: '0.0.0.0',
    port: 8080,
    baseUrl: 'https://localhost:8080',
    entityId: 'https://localhost:3000',
    dataDir: '/tmp/itw',
    configFilePath: '/tmp/config.ini',
    trustAnchorUrl: '/.well-known/openid-federation',
    x5cCertPath: '/tmp/x5c-cert.pem',
    httpsEnabled: true,
    tlsCertPath: '/tmp/tls-cert.pem',
    tlsKeyPath: '/tmp/tls-key.pem'
  };

  it('accepts a valid config', () => {
    const parsed = rpConfigSchema.safeParse(BASE_VALID);
    expect(parsed.success).toBe(true);
  });

  it('accepts httpsEnabled: true when cert and key paths are provided', () => {
    const parsed = rpConfigSchema.safeParse({
      ...BASE_VALID,
      httpsEnabled: true,
      tlsCertPath: '/tmp/tls-cert.pem',
      tlsKeyPath: '/tmp/tls-key.pem'
    });
    expect(parsed.success).toBe(true);
  });

  it('rejects httpsEnabled: true with empty tlsCertPath', () => {
    const parsed = rpConfigSchema.safeParse({
      ...BASE_VALID,
      httpsEnabled: true,
      tlsCertPath: '',
      tlsKeyPath: '/tmp/tls-key.pem'
    });
    expect(parsed.success).toBe(false);
    if (!parsed.success) {
      expect(parsed.error.issues.some((i) => i.path.includes('tlsCertPath'))).toBe(true);
    }
  });

  it('rejects httpsEnabled: true with empty tlsKeyPath', () => {
    const parsed = rpConfigSchema.safeParse({
      ...BASE_VALID,
      httpsEnabled: true,
      tlsCertPath: '/tmp/tls-cert.pem',
      tlsKeyPath: ''
    });
    expect(parsed.success).toBe(false);
    if (!parsed.success) {
      expect(parsed.error.issues.some((i) => i.path.includes('tlsKeyPath'))).toBe(true);
    }
  });

  it('rejects out-of-range ports', () => {
    const parsed = rpConfigSchema.safeParse({
      host: '0.0.0.0',
      port: 99999,
      baseUrl: 'http://localhost:99999',
      dataDir: '/tmp',
      configFilePath: '/tmp/c.ini',
      trustAnchorUrl: 'https://trust-anchor.example.com'
    });
    expect(parsed.success).toBe(false);
  });

  it('rejects missing trustAnchorUrl', () => {
    const parsed = rpConfigSchema.safeParse({
      host: '0.0.0.0',
      port: 8080,
      baseUrl: 'http://localhost:8080',
      dataDir: '/tmp/itw',
      configFilePath: '/tmp/config.ini'
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
      env: { ...REQUIRED_FIELDS_ENV }
    });

    expect(result.configFileFound).toBe(false);
    expect(result.config.host).toBe(DEFAULT_HOST);
    expect(result.config.port).toBe(DEFAULT_PORT);
    expect(result.config.dataDir).toBe(DEFAULT_DATA_DIR);
    expect(result.config.baseUrl).toBe(`http://localhost:${DEFAULT_PORT}`);
    expect(result.config.entityId).toBe(`https://localhost:3000`);
  });

  it('reads [rp].port and [global].data_dir from the ini file', () => {
    const cfgPath = join(workDir, 'config.ini');
    writeFileSync(
      cfgPath,
      `[global]\ndata_dir = /opt/itw-data\n\n[rp]\nport = 9090\nentity_id = https://rp.example.org\ntrust_anchor_url = https://trust-anchor.example.org/.well-known/openid-federation\nx5c_cert_path = /tmp/x5c-cert.pem\n`
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
    writeFileSync(cfgPath, `[rp]\nentity_id = https://rp-from-ini.example.org\n${REQUIRED_FIELDS_INI}`);

    const result = loadRpConfig({
      configFilePath: cfgPath,
      env: { ...REQUIRED_FIELDS_ENV, ITW_CT_RP_ENTITY_ID: 'https://rp-from-env.example.org' }
    });

    expect(result.config.entityId).toBe('https://rp-from-env.example.org');
  });

  it('env override ITW_CT_RP_TRUST_ANCHOR_URL wins over the ini file', () => {
    const cfgPath = join(workDir, 'config.ini');
    writeFileSync(
      cfgPath,
      `[rp]\ntrust_anchor_url = https://ta-from-ini.example.org/.well-known/openid-federation\n${REQUIRED_FIELDS_INI}`
    );

    const result = loadRpConfig({
      configFilePath: cfgPath,
      env: {
        ...REQUIRED_FIELDS_ENV,
        ITW_CT_RP_TRUST_ANCHOR_URL: 'https://ta-from-env.example.org/.well-known/openid-federation'
      }
    });

    expect(result.config.trustAnchorUrl).toBe('https://ta-from-env.example.org/.well-known/openid-federation');
  });

  it('env override ITW_CT_RP_PORT wins over the ini file', () => {
    const cfgPath = join(workDir, 'config.ini');
    writeFileSync(cfgPath, `[rp]\nport = 9090\n${REQUIRED_FIELDS_INI}`);

    const result = loadRpConfig({
      configFilePath: cfgPath,
      env: { ...REQUIRED_FIELDS_ENV, ITW_CT_RP_PORT: '12345' }
    });

    expect(result.config.port).toBe(12345);
  });

  it('env override ITW_CT_DATA_DIR wins over the ini file', () => {
    const cfgPath = join(workDir, 'config.ini');
    writeFileSync(cfgPath, `[global]\ndata_dir = /from/ini\n${REQUIRED_FIELDS_INI}`);

    const result = loadRpConfig({
      configFilePath: cfgPath,
      env: { ...REQUIRED_FIELDS_ENV, ITW_CT_DATA_DIR: '/from/env' }
    });

    expect(result.config.dataDir).toBe('/from/env');
  });

  it('invalid [rp].port in the ini file falls back to the default port', () => {
    const cfgPath = join(workDir, 'config.ini');
    writeFileSync(cfgPath, `[rp]\nport = 99999\n${REQUIRED_FIELDS_INI}`);

    const result = loadRpConfig({ configFilePath: cfgPath, env: { ...REQUIRED_FIELDS_ENV } });

    expect(result.config.port).toBe(DEFAULT_PORT);
  });

  it('rejects an invalid port in the env override', () => {
    expect(() =>
      loadRpConfig({
        configFilePath: join(workDir, 'missing.ini'),
        env: { ...REQUIRED_FIELDS_ENV, ITW_CT_RP_PORT: 'not-a-port' }
      })
    ).toThrow(/Invalid ITW_CT_RP_PORT/);
  });

  it('env override ITW_CT_RP_BASE_URL wins over the derived baseUrl', () => {
    const result = loadRpConfig({
      configFilePath: join(workDir, 'missing.ini'),
      env: { ...REQUIRED_FIELDS_ENV, ITW_CT_RP_BASE_URL: 'http://rp.example.com:9000' }
    });

    expect(result.config.baseUrl).toBe('http://rp.example.com:9000');
  });

  it('empty ITW_CT_RP_BASE_URL falls back to derived baseUrl', () => {
    const result = loadRpConfig({
      configFilePath: join(workDir, 'missing.ini'),
      env: { ...REQUIRED_FIELDS_ENV, ITW_CT_RP_BASE_URL: '' }
    });

    expect(result.config.baseUrl).toBe(`http://localhost:${DEFAULT_PORT}`);
  });

  it('whitespace-only ITW_CT_RP_BASE_URL falls back to derived baseUrl', () => {
    const result = loadRpConfig({
      configFilePath: join(workDir, 'missing.ini'),
      env: { ...REQUIRED_FIELDS_ENV, ITW_CT_RP_BASE_URL: '   ' }
    });

    expect(result.config.baseUrl).toBe(`http://localhost:${DEFAULT_PORT}`);
  });

  it('ITW_CT_RP_BASE_URL trailing slash is stripped by Zod URL normalization', () => {
    // Zod's z.string().url() uses WHATWG URL semantics which strips the trailing
    // slash from the root path (http://host:port/ → http://host:port).
    const result = loadRpConfig({
      configFilePath: join(workDir, 'missing.ini'),
      env: { ...REQUIRED_FIELDS_ENV, ITW_CT_RP_BASE_URL: 'http://rp.example.com:9000/' }
    });

    expect(result.config.baseUrl).toBe('http://rp.example.com:9000');
  });

  it('reads trustAnchorUrl from env', () => {
    const result = loadRpConfig({
      configFilePath: join(workDir, 'missing.ini'),
      env: {
        ITW_CT_RP_TRUST_ANCHOR_URL: 'https://ta.example.org'
      }
    });

    expect(result.config.trustAnchorUrl).toBe('https://ta.example.org');
  });

  it('reads trustAnchorUrl from the ini file', () => {
    const cfgPath = join(workDir, 'config.ini');
    writeFileSync(cfgPath, '[rp]\nport = 8080\ntrust_anchor_url = https://ta.from.ini\nx5c_cert_path = /ini/x5c.pem\n');

    const result = loadRpConfig({ configFilePath: cfgPath, env: {} });

    expect(result.config.trustAnchorUrl).toBe('https://ta.from.ini');
  });

  it('env ITW_CT_RP_TRUST_ANCHOR_URL wins over the ini file', () => {
    const cfgPath = join(workDir, 'config.ini');
    writeFileSync(cfgPath, `[rp]\ntrust_anchor_url = https://ta.from.ini\n${REQUIRED_FIELDS_INI}`);

    const result = loadRpConfig({
      configFilePath: cfgPath,
      env: { ...REQUIRED_FIELDS_ENV, ITW_CT_RP_TRUST_ANCHOR_URL: 'https://ta.from.env' }
    });

    expect(result.config.trustAnchorUrl).toBe('https://ta.from.env');
  });

  it('defaults httpsEnabled to false when ITW_CT_HTTPS is not set', () => {
    const result = loadRpConfig({
      configFilePath: join(workDir, 'missing.ini'),
      env: { ...REQUIRED_FIELDS_ENV }
    });
    expect(result.config.httpsEnabled).toBe(false);
    expect(result.config.tlsCertPath).toBe(join(result.config.dataDir, 'tls-cert.pem'));
    expect(result.config.tlsKeyPath).toBe(join(result.config.dataDir, 'tls-key.pem'));
  });

  it('sets httpsEnabled to true when ITW_CT_HTTPS=true', () => {
    const result = loadRpConfig({
      configFilePath: join(workDir, 'missing.ini'),
      env: { ...REQUIRED_FIELDS_ENV, ITW_CT_HTTPS: 'true' }
    });
    expect(result.config.httpsEnabled).toBe(true);
  });

  it('sets httpsEnabled to true when ITW_CT_HTTPS=1', () => {
    const result = loadRpConfig({
      configFilePath: join(workDir, 'missing.ini'),
      env: { ...REQUIRED_FIELDS_ENV, ITW_CT_HTTPS: '1' }
    });
    expect(result.config.httpsEnabled).toBe(true);
  });

  it('sets httpsEnabled to false when ITW_CT_HTTPS=false', () => {
    const result = loadRpConfig({
      configFilePath: join(workDir, 'missing.ini'),
      env: { ...REQUIRED_FIELDS_ENV, ITW_CT_HTTPS: 'false' }
    });
    expect(result.config.httpsEnabled).toBe(false);
  });

  it('reads httpsEnabled from [global] https = true in the INI file', () => {
    const cfgPath = join(workDir, 'config.ini');
    writeFileSync(cfgPath, `[global]\nhttps = true\n${REQUIRED_FIELDS_INI}`);

    const result = loadRpConfig({ configFilePath: cfgPath, env: {} });
    expect(result.config.httpsEnabled).toBe(true);
  });

  it('env ITW_CT_HTTPS=false overrides [global] https = true in the INI file', () => {
    const cfgPath = join(workDir, 'config.ini');
    writeFileSync(cfgPath, `[global]\nhttps = true\n${REQUIRED_FIELDS_INI}`);

    const result = loadRpConfig({ configFilePath: cfgPath, env: { ITW_CT_HTTPS: 'false' } });
    expect(result.config.httpsEnabled).toBe(false);
  });

  it('reads tlsCertPath and tlsKeyPath from env when explicitly set', () => {
    const result = loadRpConfig({
      configFilePath: join(workDir, 'missing.ini'),
      env: {
        ...REQUIRED_FIELDS_ENV,
        ITW_CT_HTTPS: 'true',
        ITW_CT_TLS_CERT_PATH: '/certs/server.pem',
        ITW_CT_TLS_KEY_PATH: '/keys/server-key.pem'
      }
    });
    expect(result.config.tlsCertPath).toBe('/certs/server.pem');
    expect(result.config.tlsKeyPath).toBe('/keys/server-key.pem');
  });

  it('expands ~ in ITW_CT_TLS_CERT_PATH and ITW_CT_TLS_KEY_PATH', () => {
    const result = loadRpConfig({
      configFilePath: join(workDir, 'missing.ini'),
      env: {
        ...REQUIRED_FIELDS_ENV,
        ITW_CT_HTTPS: 'true',
        ITW_CT_TLS_CERT_PATH: '~/certs/cert.pem',
        ITW_CT_TLS_KEY_PATH: '~/certs/key.pem'
      }
    });
    expect(result.config.tlsCertPath).not.toContain('~');
    expect(result.config.tlsCertPath).toContain('certs/cert.pem');
    expect(result.config.tlsKeyPath).not.toContain('~');
    expect(result.config.tlsKeyPath).toContain('certs/key.pem');
  });

  it('derives tlsCertPath and tlsKeyPath from dataDir when env vars are not set', () => {
    const result = loadRpConfig({
      configFilePath: join(workDir, 'missing.ini'),
      env: { ...REQUIRED_FIELDS_ENV, ITW_CT_HTTPS: 'true' }
    });
    expect(result.config.tlsCertPath).toBe(join(result.config.dataDir, 'tls-cert.pem'));
    expect(result.config.tlsKeyPath).toBe(join(result.config.dataDir, 'tls-key.pem'));
  });

  it('derives tlsCertPath and tlsKeyPath from dataDir when HTTPS comes from the INI file', () => {
    const cfgPath = join(workDir, 'config.ini');
    writeFileSync(cfgPath, `[global]\nhttps = true\ndata_dir = /opt/itw-data\n${REQUIRED_FIELDS_INI}`);

    const result = loadRpConfig({ configFilePath: cfgPath, env: {} });

    expect(result.config.httpsEnabled).toBe(true);
    expect(result.config.tlsCertPath).toBe('/opt/itw-data/tls-cert.pem');
    expect(result.config.tlsKeyPath).toBe('/opt/itw-data/tls-key.pem');
  });

  it('derives https baseUrl when ITW_CT_HTTPS is enabled and no explicit base URL', () => {
    const result = loadRpConfig({
      configFilePath: join(workDir, 'missing.ini'),
      env: { ...REQUIRED_FIELDS_ENV, ITW_CT_HTTPS: 'true' }
    });
    expect(result.config.baseUrl).toMatch(/^https:\/\//);
  });

  it('explicit ITW_CT_RP_BASE_URL wins over https-derived baseUrl', () => {
    const result = loadRpConfig({
      configFilePath: join(workDir, 'missing.ini'),
      env: {
        ...REQUIRED_FIELDS_ENV,
        ITW_CT_HTTPS: 'true',
        ITW_CT_RP_BASE_URL: 'http://rp.example.com:8080'
      }
    });
    expect(result.config.baseUrl).toBe('http://rp.example.com:8080');
  });
});
