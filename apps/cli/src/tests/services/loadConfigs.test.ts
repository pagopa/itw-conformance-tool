import { parseINI, type ConfigType } from '@itw-conformance-tool/config';
import { describe, it, expect, vi, beforeEach } from 'vitest';

import { loadConfigs } from '../../services/loadConfigs.js';
import { existsFileSync } from '../../utils/search.js';

import type { Level } from '@itw-conformance-tool/logger';

vi.mock('../../utils/search.js');

vi.mock('../../templates/templates.js', () => ({
  getDefaultConfigs: vi.fn((rootPath: string) => ({
    global: {
      data_dir: `${rootPath}/.itw-conformance-tool`,
      log_level: 'info',
      https: false
    },
    'itw-credential-issuer': { auth_flow: 'direct', port: 3000, credential_types: 'pid,mdl,badge,eaa' },
    rp: { port: 8080 }
  }))
}));

vi.mock('@itw-conformance-tool/config', () => ({
  parseINI: vi.fn()
}));

const rootPath = '/root';

const parsedConfigs: ConfigType = {
  global: {
    data_dir: '/custom/.itw-conformance-tool',
    log_level: 'warn',
    https: false
  },
  'itw-credential-issuer': { auth_flow: 'direct', port: 4000, credential_types: 'pid' },
  rp: {
    port: 9090,
    entity_id: 'https://rp.example.com',
    trust_anchor_url: 'https://trust-anchor.example.com',
    signing_key_path: '/custom/rp/signing-key.pem',
    x5c_cert_path: '/custom/rp/x5c-cert.pem'
  }
};

describe('loadConfigs', () => {
  let emitLog: (event: string, type?: Level) => void;

  beforeEach(() => {
    vi.clearAllMocks();
    emitLog = vi.fn<(event: string, type?: Level) => void>();
  });

  describe('with explicit config flag (flags.config.value = true)', () => {
    it('returns parsed configs when the file exists and parseINI succeeds', () => {
      vi.mocked(existsFileSync).mockReturnValue(true);
      vi.mocked(parseINI).mockReturnValue({ ok: true, data: parsedConfigs });

      const flags = {
        issuer: false,
        rp: false,
        all: false,
        force: false,
        config: { value: true, path: '/custom/config.ini' }
      };
      const result = loadConfigs(flags, rootPath, emitLog);

      expect(result.configFileExists).toBe(true);
      expect(result.configs['itw-credential-issuer'].port).toBe(4000);
      expect(emitLog).toHaveBeenCalledWith(expect.stringContaining('/custom/config.ini'));
    });

    it('returns default configs and logs warn when file exists but parseINI fails', () => {
      vi.mocked(existsFileSync).mockReturnValue(true);
      vi.mocked(parseINI).mockReturnValue({ ok: false, error: 'Invalid INI', data: parsedConfigs });

      const flags = {
        issuer: false,
        rp: false,
        all: false,
        force: false,
        config: { value: true, path: '/custom/config.ini' }
      };
      const result = loadConfigs(flags, rootPath, emitLog);

      expect(result.configFileExists).toBe(false);
      expect(result.configs.global.log_level).toBe('info');
      expect(emitLog).toHaveBeenCalledWith(expect.stringContaining('could not be parsed'), 'warn');
    });

    it('returns default configs and logs when the file does not exist', () => {
      vi.mocked(existsFileSync).mockReturnValue(false);

      const flags = {
        issuer: false,
        rp: false,
        all: false,
        force: false,
        config: { value: true, path: '/custom/config.ini' }
      };
      const result = loadConfigs(flags, rootPath, emitLog);

      expect(result.configFileExists).toBe(false);
      expect(result.configs.global.log_level).toBe('info');
      expect(emitLog).toHaveBeenCalledWith(expect.stringContaining('not found at specified path'));
    });
  });

  describe('without explicit config flag (flags.config.value = false)', () => {
    it('returns parsed configs when default config.ini exists and parseINI succeeds', () => {
      vi.mocked(existsFileSync).mockReturnValue(true);
      vi.mocked(parseINI).mockReturnValue({ ok: true, data: parsedConfigs });

      const flags = { issuer: false, rp: false, all: false, force: false, config: { value: false, path: '' } };
      const result = loadConfigs(flags, rootPath, emitLog);

      expect(result.configFileExists).toBe(true);
      expect(result.configs['itw-credential-issuer'].port).toBe(4000);
      expect(emitLog).toHaveBeenCalledWith(expect.stringContaining('config.ini'));
    });

    it('returns default configs and logs warn when default config.ini exists but parseINI fails', () => {
      vi.mocked(existsFileSync).mockReturnValue(true);
      vi.mocked(parseINI).mockReturnValue({ ok: false, error: 'Bad format', data: parsedConfigs });

      const flags = { issuer: false, rp: false, all: false, force: false, config: { value: false, path: '' } };
      const result = loadConfigs(flags, rootPath, emitLog);

      expect(result.configFileExists).toBe(false);
      expect(result.configs.global.log_level).toBe('info');
      expect(emitLog).toHaveBeenCalledWith(expect.stringContaining('could not be parsed'), 'warn');
    });

    it('returns default configs and logs when default config.ini does not exist', () => {
      vi.mocked(existsFileSync).mockReturnValue(false);

      const flags = { issuer: false, rp: false, all: false, force: false, config: { value: false, path: '' } };
      const result = loadConfigs(flags, rootPath, emitLog);

      expect(result.configFileExists).toBe(false);
      expect(result.configs.global.log_level).toBe('info');
      expect(emitLog).toHaveBeenCalledWith(expect.stringContaining('not found at default path'));
    });
  });
});
