import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync, type Stats } from 'node:fs';

import { parseINI } from '@itw-conformance-tool/config';
import { describe, it, expect, vi, beforeEach } from 'vitest';

import { init } from '../../commands/init.js';
import { createSelfSignedCertificateFromJwk, getTlsCertAndKey } from '../../utils/certificates.js';
import { expandPath } from '../../utils/path.js';
import { existsFileSync } from '../../utils/search.js';

import type { CLIFlags } from '../../types/types.js';
import type { ConfigType } from '@itw-conformance-tool/config';

vi.mock('node:fs', () => ({
  existsSync: vi.fn(),
  statSync: vi.fn(),
  mkdirSync: vi.fn(),
  readFileSync: vi.fn(() => '{"kty":"EC","crv":"P-256","x":"x","y":"y","d":"d"}'),
  writeFileSync: vi.fn()
}));

vi.mock('../../utils/search.js');

vi.mock('../../utils/path.js', () => ({
  expandPath: vi.fn((p: string) => p)
}));

vi.mock('../../utils/crypto.js', () => ({
  getAuthRequestKey: vi.fn(() => '{"kty":"EC","crv":"P-256","x":"x","y":"y","d":"d"}'),
  getAuthResponseKey: vi.fn(() => '{"kty":"EC"}'),
  getFederationKey: vi.fn(() => '{"kty":"EC"}'),
  getSigningKeys: vi.fn(() => '{"keys":[]}')
}));

vi.mock('../../utils/certificates.js', () => ({
  createSelfSignedCertificateFromJwk: vi.fn(() => '---X5C-CERT---'),
  getIACAChain: vi.fn(() => ({ certificate: '---CERT---', privateKey: '---KEY---' })),
  getTlsCertAndKey: vi.fn(() => ({ cert: '---TLS-CERT---', key: '---TLS-KEY---' }))
}));

vi.mock('../../templates/templates.js', () => ({
  configINITemplate: '[global]\ndata_dir=~/.itw-conformance-tool\n'
}));

vi.mock('@itw-conformance-tool/config', () => ({
  parseINI: vi.fn(),
  ConfigINITemplate: '[global]\ndata_dir=~/.itw-conformance-tool\n'
}));

const baseFlags: CLIFlags = {
  issuer: false,
  rp: false,
  all: false,
  force: false,
  config: { value: false, path: '' },
  runId: undefined,
  format: 'html'
};

const makeConfigs = (): ConfigType => ({
  global: {
    data_dir: '/root/.itw-conformance-tool',
    log_level: 'info',
    https: false
  },
  'itw-credential-issuer': { auth_flow: 'direct', port: 3000, credential_types: 'pid' },
  rp: { port: 8080, entity_id: 'https://127.0.0.1:3000', trust_anchor_url: '' }
});

describe('init', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // config.ini exists; no other files exist (so they will be generated)
    vi.mocked(existsFileSync).mockImplementation((p) => String(p).endsWith('config.ini'));
    vi.mocked(expandPath).mockImplementation((p: string) => p);
    vi.mocked(parseINI).mockReturnValue({ ok: true, data: makeConfigs() });
    // data_dir does not exist
    vi.mocked(existsSync).mockReturnValue(false);
  });

  it('creates the data, issuer, and rp directories', async () => {
    await init(baseFlags);

    expect(mkdirSync).toHaveBeenCalledWith('/root/.itw-conformance-tool', { recursive: true });
    expect(mkdirSync).toHaveBeenCalledWith('/root/.itw-conformance-tool/issuer', { recursive: true });
    expect(mkdirSync).toHaveBeenCalledWith('/root/.itw-conformance-tool/rp', { recursive: true });
  });

  it('skips TLS files when https is false', async () => {
    await init(baseFlags);

    expect(getTlsCertAndKey).not.toHaveBeenCalled();
    const writtenPaths = vi.mocked(writeFileSync).mock.calls.map((c) => c[0]);
    expect(writtenPaths).not.toContain('/root/.itw-conformance-tool/tls-cert.pem');
    expect(writtenPaths).not.toContain('/root/.itw-conformance-tool/tls-key.pem');
  });

  it('writes TLS files when https is true and they do not exist', async () => {
    vi.mocked(parseINI).mockReturnValue({
      ok: true,
      data: { ...makeConfigs(), global: { ...makeConfigs().global, https: true } }
    });

    await init(baseFlags);

    expect(getTlsCertAndKey).toHaveBeenCalledOnce();
    const writtenPaths = vi.mocked(writeFileSync).mock.calls.map((c) => c[0]);
    expect(writtenPaths).toContain('/root/.itw-conformance-tool/tls-cert.pem');
    expect(writtenPaths).toContain('/root/.itw-conformance-tool/tls-key.pem');
  });

  it('skips TLS files when they already exist and --force is not set', async () => {
    vi.mocked(existsFileSync).mockReturnValue(true);
    vi.mocked(existsSync).mockReturnValue(true);
    vi.mocked(statSync).mockReturnValue({ isDirectory: () => true } as unknown as Stats);
    vi.mocked(parseINI).mockReturnValue({
      ok: true,
      data: { ...makeConfigs(), global: { ...makeConfigs().global, https: true } }
    });

    await init(baseFlags);

    expect(getTlsCertAndKey).not.toHaveBeenCalled();
  });

  it('overwrites TLS files when --force is set', async () => {
    vi.mocked(existsFileSync).mockReturnValue(true);
    vi.mocked(existsSync).mockReturnValue(true);
    vi.mocked(statSync).mockReturnValue({ isDirectory: () => true } as unknown as Stats);
    vi.mocked(parseINI).mockReturnValue({
      ok: true,
      data: { ...makeConfigs(), global: { ...makeConfigs().global, https: true } }
    });

    await init({ ...baseFlags, force: true });

    expect(getTlsCertAndKey).toHaveBeenCalledOnce();
  });

  it('skips config.ini when it already exists and --force is not set', async () => {
    await init(baseFlags);

    const configWrites = vi.mocked(writeFileSync).mock.calls.filter((c) => String(c[0]).endsWith('config.ini'));
    expect(configWrites).toHaveLength(0);
  });

  it('creates config.ini when it does not exist', async () => {
    vi.mocked(existsFileSync).mockReturnValue(false);

    await init(baseFlags);

    const configWrites = vi.mocked(writeFileSync).mock.calls.filter((c) => String(c[0]).endsWith('config.ini'));
    expect(configWrites).toHaveLength(1);
  });

  it('generates IACA cert and key when they do not exist', async () => {
    await init(baseFlags);

    const writtenPaths = vi.mocked(writeFileSync).mock.calls.map((c) => c[0]);
    expect(writtenPaths).toContain('/root/.itw-conformance-tool/issuer/iaca-cert.pem');
    expect(writtenPaths).toContain('/root/.itw-conformance-tool/issuer/iaca-key.pem');
  });

  it('generates signing keys when they do not exist', async () => {
    await init(baseFlags);

    const writtenPaths = vi.mocked(writeFileSync).mock.calls.map((c) => c[0]);
    expect(writtenPaths).toContain('/root/.itw-conformance-tool/issuer/signing-keys.jwks.json');
  });

  it('generates auth request, auth response, and federation keys when they do not exist', async () => {
    await init(baseFlags);

    const writtenPaths = vi.mocked(writeFileSync).mock.calls.map((c) => c[0]);
    expect(writtenPaths).toContain('/root/.itw-conformance-tool/rp/auth-request-key.jwk.json');
    expect(writtenPaths).toContain('/root/.itw-conformance-tool/rp/auth-response-key.jwk.json');
    expect(writtenPaths).toContain('/root/.itw-conformance-tool/rp/federation-key.jwk.json');
    expect(writtenPaths).toContain('/root/.itw-conformance-tool/rp/x5c-cert.pem');
    expect(createSelfSignedCertificateFromJwk).toHaveBeenCalledWith({
      kty: 'EC',
      crv: 'P-256',
      x: 'x',
      y: 'y',
      d: 'd'
    });
    expect(readFileSync).not.toHaveBeenCalled();
  });

  it('reuses existing auth request key file when generating only x5c certificate', async () => {
    vi.mocked(existsFileSync).mockImplementation((p) => {
      const path = String(p);
      if (path.endsWith('config.ini')) return true;
      if (path.endsWith('/rp/x5c-cert.pem')) return false;
      return true;
    });
    vi.mocked(existsSync).mockReturnValue(true);
    vi.mocked(statSync).mockReturnValue({ isDirectory: () => true } as unknown as Stats);

    await init(baseFlags);

    expect(readFileSync).toHaveBeenCalledWith('/root/.itw-conformance-tool/rp/auth-request-key.jwk.json', 'utf8');
    expect(createSelfSignedCertificateFromJwk).toHaveBeenCalledWith({
      kty: 'EC',
      crv: 'P-256',
      x: 'x',
      y: 'y',
      d: 'd'
    });
  });

  it('skips relying-party keys when they already exist and --force is not set', async () => {
    vi.mocked(existsFileSync).mockReturnValue(true);
    vi.mocked(existsSync).mockReturnValue(true);
    vi.mocked(statSync).mockReturnValue({ isDirectory: () => true } as unknown as Stats);

    await init(baseFlags);

    const writtenPaths = vi.mocked(writeFileSync).mock.calls.map((c) => c[0]);
    expect(writtenPaths).not.toContain('/root/.itw-conformance-tool/rp/auth-request-key.jwk.json');
    expect(writtenPaths).not.toContain('/root/.itw-conformance-tool/rp/auth-response-key.jwk.json');
    expect(writtenPaths).not.toContain('/root/.itw-conformance-tool/rp/federation-key.jwk.json');
  });
});
