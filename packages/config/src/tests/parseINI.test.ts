import { existsSync, readFileSync } from 'node:fs';

import { describe, it, expect, vi, beforeEach } from 'vitest';

import { DEFAULT_CONFIG } from '../schemas/schemas.js';
import { parseINI } from '../services/parseINI.js';

vi.mock('node:fs', () => ({
  existsSync: vi.fn(),
  readFileSync: vi.fn()
}));

const validConfigContent = `[global]
data_dir=~/.itw-conformance-tool
log_level=warn

[itw-credential-issuer]
auth_flow=l2plus
port=4000
credential_types=pid,mdl,badge,eaa

[rp]
entity_id=https://rp.example.org
port=8080
x5c_cert_path=/tmp/x5c-cert.pem
trust_anchor_url=https://trust-anchor.example.com
`;

const httpsConfigContent = `[global]
data_dir=~/.itw-conformance-tool
log_level=info
https=true

[itw-credential-issuer]
auth_flow=direct
port=3000
credential_types=pid

[rp]
port=8080
`;

const emptyConfigContent = ``;
const missingSectionContent = `[global]
log_level=info
`;
const extraKeysContent = `[global]
data_dir=~/.itw-conformance-tool
log_level=warn
extra_key=foo

[itw-credential-issuer]
port=4000
credential_types=pid,mdl,badge,eaa

[rp]
entity_id=https://rp.example.org
port=8080
trust_anchor=https://trust-anchor.example.org/.well-known/openid-federation
`;
const wrongTypeContent = `[global]
data_dir=~/.itw-conformance-tool
log_level=warn

[itw-credential-issuer]
auth_flow=notavalid
port=notanumber
credential_types=pi

[rp]
port=8080
`;

describe('parseINI', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns default config when file does not exist', () => {
    vi.mocked(existsSync).mockReturnValue(false);

    const result = parseINI('/missing/config.ini');

    expect(result.ok).toBe(false);
    expect(result.data).toEqual(DEFAULT_CONFIG);
  });

  it('parses and validates a valid ini config', () => {
    vi.mocked(existsSync).mockReturnValue(true);
    vi.mocked(readFileSync).mockReturnValue(validConfigContent);
    const result = parseINI('./config.example.ini');
    expect(result.ok).toBe(true);
    expect(result.data).toEqual({
      global: {
        data_dir: '~/.itw-conformance-tool',
        log_level: 'warn',
        https: false
      },
      'itw-credential-issuer': {
        auth_flow: 'l2plus',
        port: 4000,
        credential_types: 'pid,mdl,badge,eaa'
      },
      rp: {
        port: 8080,
        entity_id: 'https://rp.example.org',
        x5c_cert_path: '/tmp/x5c-cert.pem',
        trust_anchor_url: 'https://trust-anchor.example.com'
      }
    });
  });

  it('parses https=true', () => {
    vi.mocked(existsSync).mockReturnValue(true);
    vi.mocked(readFileSync).mockReturnValue(httpsConfigContent);
    const result = parseINI('./https-config.ini');
    expect(result.ok).toBe(true);
    expect(result.data.global.https).toBe(true);
  });

  it('defaults https to false when key is absent', () => {
    vi.mocked(existsSync).mockReturnValue(true);
    vi.mocked(readFileSync).mockReturnValue(validConfigContent);
    const result = parseINI('./config.example.ini');
    expect(result.ok).toBe(true);
    expect(result.data.global.https).toBe(false);
  });

  it('returns default config for empty config file', () => {
    vi.mocked(existsSync).mockReturnValue(true);
    vi.mocked(readFileSync).mockReturnValue(emptyConfigContent);
    const result = parseINI('./files/config.empty.ini');
    expect(result.ok).toBe(true);
    expect(result.data).toEqual(DEFAULT_CONFIG);
    expect('error' in result).toBe(false);
  });

  it('returns default config for missing section', () => {
    vi.mocked(existsSync).mockReturnValue(true);
    vi.mocked(readFileSync).mockReturnValue(missingSectionContent);
    const result = parseINI('./missing-section.ini');
    expect(result.ok).toBe(true);
    expect(result.data).toEqual(DEFAULT_CONFIG);
    expect('error' in result).toBe(false);
  });

  it('returns default config for extra keys', () => {
    vi.mocked(existsSync).mockReturnValue(true);
    vi.mocked(readFileSync).mockReturnValue(extraKeysContent);
    const result = parseINI('./extra-keys.ini');
    expect(result.ok).toBe(true);
    expect(result.data).toEqual({
      global: {
        data_dir: '~/.itw-conformance-tool',
        log_level: 'warn',
        https: false
      },
      'itw-credential-issuer': {
        auth_flow: 'direct',
        port: 4000,
        credential_types: 'pid,mdl,badge,eaa'
      },
      rp: {
        port: 8080,
        entity_id: 'https://rp.example.org',
        x5c_cert_path: '~/.itw-conformance-tool/rp/x5c-cert.pem',
        trust_anchor_url: ''
      }
    });
    expect('error' in result).toBe(false);
  });

  it('returns default config for wrong type', () => {
    vi.mocked(existsSync).mockReturnValue(true);
    vi.mocked(readFileSync).mockReturnValue(wrongTypeContent);
    const result = parseINI('./wrong-type.ini');
    expect(result.ok).toBe(true);
    expect(result.data).toEqual({
      global: {
        data_dir: '~/.itw-conformance-tool',
        log_level: 'warn',
        https: false
      },
      'itw-credential-issuer': {
        auth_flow: 'direct',
        port: 3000,
        credential_types: 'pid,mdl,badge,eaa'
      },
      rp: {
        port: 8080,
        entity_id: '',
        x5c_cert_path: '~/.itw-conformance-tool/rp/x5c-cert.pem',
        trust_anchor_url: ''
      }
    });
    expect('error' in result).toBe(false);
  });

  it('handles unreadable files', () => {
    vi.mocked(existsSync).mockReturnValue(true);
    vi.mocked(readFileSync).mockImplementation(() => {
      throw new Error('EACCES: permission denied');
    });

    const result = parseINI('/protected/config.ini');

    expect(result.ok).toBe(false);
    // @ts-expect-error - It should return an error message containing "permission denied" and the default config
    expect(result.error).toContain('permission denied');
    expect(result.data).toEqual(DEFAULT_CONFIG);
  });

  it('handles generic unknown errors', () => {
    vi.mocked(existsSync).mockReturnValue(true);
    vi.mocked(readFileSync).mockImplementation(() => {
      throw 'unexpected failure';
    });

    const result = parseINI('/broken/config.ini');

    expect(result.ok).toBe(false);
    // @ts-expect-error - It should return an error message containing "unexpected failure" and the default config
    expect(result.error).toContain('unexpected failure');
    expect(result.data).toEqual(DEFAULT_CONFIG);
  });
});
