import { describe, it, expect, vi, beforeEach } from 'vitest';

import { buildEnv } from '../../services/buildEnv.js';

import type { LogLevel } from '../../types/types.js';
import type { ConfigType } from '@itw-conformance-tool/config';

const mockConfigs: ConfigType = {
  global: {
    data_dir: '/data/.itw-conformance-tool',
    log_level: 'info',
    https: true
  },
  'itw-credential-issuer': {
    auth_flow: 'l3',
    port: 3000,
    credential_types: 'pid,mdl,badge,eaa'
  },
  rp: {
    port: 8080,
    entity_id: 'https://rp.example.com',
    trust_anchor_url: 'https://trust-anchor.example.com'
  }
};

describe('buildEnv', () => {
  let emitLog: (event: string, type?: LogLevel) => void;

  beforeEach(() => {
    vi.clearAllMocks();
    emitLog = vi.fn<(event: string, type?: LogLevel) => void>();
  });

  it('includes all expected ITW_CT_ environment variables', () => {
    const env = buildEnv(mockConfigs, emitLog);

    expect(env.ITW_CT_DATA_DIR).toBe('/data/.itw-conformance-tool');
    expect(env.ITW_CT_LOG_LEVEL).toBe('info');
    expect(env.ITW_CT_HTTPS).toBe('true');
    expect(env.ITW_CT_ISSUER_PORT).toBe('3000');
    expect(env.ITW_CT_ISSUER_CREDENTIAL_TYPES).toBe('pid,mdl,badge,eaa');
    expect(env.ITW_CT_RP_PORT).toBe('8080');
    expect(env.ITW_CT_RP_BASE_URL).toBe('https://127.0.0.1:8080');
    expect(env.ITW_CT_ISSUER_AUTH_FLOW).toBe('l3');
    expect(env.ITW_CT_RP_TRUST_ANCHOR_URL).toBe('https://trust-anchor.example.com');
  });

  it('merges with existing process.env variables', () => {
    const env = buildEnv(mockConfigs, emitLog) as NodeJS.ProcessEnv;
    expect(env.PATH).toBe(process.env.PATH);
  });

  it('overrides process.env with ITW_CT_ values when a conflict exists', () => {
    const original = process.env.ITW_CT_LOG_LEVEL;
    process.env.ITW_CT_LOG_LEVEL = 'existing-value';

    const env = buildEnv(mockConfigs, emitLog);
    expect(env.ITW_CT_LOG_LEVEL).toBe('info');

    if (original === undefined) {
      delete process.env.ITW_CT_LOG_LEVEL;
    } else {
      process.env.ITW_CT_LOG_LEVEL = original;
    }
  });

  it('converts numeric port values to strings', () => {
    const configs: ConfigType = {
      ...mockConfigs,
      'itw-credential-issuer': { auth_flow: 'l3', port: 4000, credential_types: 'pid' },
      rp: {
        port: 9090,
        entity_id: 'https://rp.example.com',
        trust_anchor_url: 'https://ta.example.com'
      }
    };

    const env = buildEnv(configs, emitLog);

    expect(env.ITW_CT_ISSUER_PORT).toBe('4000');
    expect(env.ITW_CT_RP_PORT).toBe('9090');
    expect(env.ITW_CT_RP_BASE_URL).toBe('https://127.0.0.1:9090');
  });

  it('sets ITW_CT_HTTPS to "false" when https is disabled in config', () => {
    const configs: ConfigType = {
      ...mockConfigs,
      global: { ...mockConfigs.global, https: false }
    };

    const env = buildEnv(configs, emitLog);

    expect(env.ITW_CT_HTTPS).toBe('false');
  });
});
