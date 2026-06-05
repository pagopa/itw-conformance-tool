import { mkdirSync, writeFileSync } from 'node:fs';

import { parseINI } from '@itw-conformance-tool/config';
import { describe, it, expect, vi, beforeEach } from 'vitest';

import { init } from '../../services/init.js';
import { getTlsCertAndKey } from '../../utils/crypto.js';
import { existsFileSync, expandPath } from '../../utils/search.js';

import type { CLIFlags } from '../../types/types.js';
import type { ConfigType } from '@itw-conformance-tool/config';
import type { Level } from '@itw-conformance-tool/logger';

vi.mock('node:fs', () => ({
  mkdirSync: vi.fn(),
  writeFileSync: vi.fn()
}));

vi.mock('../../utils/search.js');

vi.mock('../../utils/crypto.js', () => ({
  getSigningKeys: vi.fn(() => '{"keys":[]}'),
  getAuthRequestKey: vi.fn(() => '{"kty":"EC"}'),
  getAuthResponseKey: vi.fn(() => '{"kty":"EC"}'),
  getIACAChain: vi.fn(() => ({ certificate: '---CERT---', privateKey: '---KEY---' })),
  getTlsCertAndKey: vi.fn(() => ({ cert: '---TLS-CERT---', key: '---TLS-KEY---' }))
}));

vi.mock('../../templates/templates.js', () => ({
  configINITemplate: '[global]\ndata_dir=~/.itw-conformance-tool\n'
}));

vi.mock('@itw-conformance-tool/config', () => ({
  parseINI: vi.fn()
}));

const rootPath = '/root';

const baseFlags: CLIFlags = {
  issuer: false,
  rp: false,
  all: false,
  force: false,
  config: { value: false, path: '' }
};

const makeConfigs = (https: boolean): ConfigType => ({
  global: {
    data_dir: '/root/.itw-conformance-tool',
    log_level: 'info',
    https
  },
  'itw-credential-issuer': { auth_flow: 'direct', port: 3000, credential_types: 'pid' },
  rp: { port: 8080, entity_id: '', trust_anchor_url: '', signing_key_path: '', x5c_cert_path: '' }
});

describe('init', () => {
  let emitter: (event: string, type?: Level) => void;

  beforeEach(() => {
    vi.clearAllMocks();
    emitter = vi.fn();
    // By default: config file exists (so configs are NOT reassigned by parseINI),
    // all other files do not exist (so they will be generated).
    vi.mocked(existsFileSync).mockImplementation((p) => String(p).endsWith('config.ini'));
    vi.mocked(expandPath).mockImplementation((p: string) => p);
  });

  it('creates the data, issuer, and rp directories', () => {
    init(rootPath, baseFlags, makeConfigs(false), emitter);

    expect(mkdirSync).toHaveBeenCalledWith('/root/.itw-conformance-tool', { recursive: true });
    expect(mkdirSync).toHaveBeenCalledWith('/root/.itw-conformance-tool/issuer', { recursive: true });
    expect(mkdirSync).toHaveBeenCalledWith('/root/.itw-conformance-tool/rp', { recursive: true });
  });

  it('does not write TLS files when https is false', () => {
    init(rootPath, baseFlags, makeConfigs(false), emitter);

    expect(getTlsCertAndKey).not.toHaveBeenCalled();
    const writtenPaths = vi.mocked(writeFileSync).mock.calls.map((c) => c[0]);
    expect(writtenPaths).not.toContain('/root/.itw-conformance-tool/tls_cert.pem');
    expect(writtenPaths).not.toContain('/root/.itw-conformance-tool/tls_key.pem');
  });

  it('writes TLS files when https is true', () => {
    init(rootPath, baseFlags, makeConfigs(true), emitter);

    expect(getTlsCertAndKey).toHaveBeenCalledOnce();
    const writtenPaths = vi.mocked(writeFileSync).mock.calls.map((c) => c[0]);
    expect(writtenPaths).toContain('/root/.itw-conformance-tool/tls_cert.pem');
    expect(writtenPaths).toContain('/root/.itw-conformance-tool/tls_key.pem');
  });

  it('skips TLS files when https is true but they already exist and --force is not set', () => {
    // All files exist
    vi.mocked(existsFileSync).mockReturnValue(true);

    init(rootPath, baseFlags, makeConfigs(true), emitter);

    expect(getTlsCertAndKey).not.toHaveBeenCalled();
  });

  it('overwrites TLS files when https is true and --force is set', () => {
    // All files exist; --force causes config to be re-read via parseINI: return https: true
    vi.mocked(existsFileSync).mockReturnValue(true);
    vi.mocked(parseINI).mockReturnValueOnce({ ok: true, data: makeConfigs(true) });

    init(rootPath, { ...baseFlags, force: true }, makeConfigs(true), emitter);

    expect(getTlsCertAndKey).toHaveBeenCalledOnce();
  });

  it('reports HTTPS disabled when https is false', () => {
    init(rootPath, baseFlags, makeConfigs(false), emitter);

    const summary = vi.mocked(emitter).mock.calls.find((c) => String(c[0]).includes('Summary'));
    expect(summary?.[0]).toContain('HTTPS disabled');
  });
});
