import { parse } from 'ini';
import { describe, expect, it } from 'vitest';

import { ConfigIniTemplate, ConfigSchema, DEFAULT_CONFIG } from '../schemas.js';

describe('ConfigIniTemplate', () => {
  it('is generated from DEFAULT_CONFIG', () => {
    expect(ConfigIniTemplate).toContain(`data_dir = ${DEFAULT_CONFIG.global.data_dir}`);
    expect(ConfigIniTemplate).toContain(`log_level = ${DEFAULT_CONFIG.global.log_level}`);
    expect(ConfigIniTemplate).toContain(`https = ${DEFAULT_CONFIG.global.https}`);
    expect(ConfigIniTemplate).toContain(
      `wallet_provider_backend_url = ${DEFAULT_CONFIG.global.wallet_provider_backend_url}`
    );
    expect(ConfigIniTemplate).toContain(`auth_flow = ${DEFAULT_CONFIG['itw-credential-issuer'].auth_flow}`);
    expect(ConfigIniTemplate).toContain(`port = ${DEFAULT_CONFIG['itw-credential-issuer'].port}`);
    expect(ConfigIniTemplate).toContain(
      `credential_types = ${DEFAULT_CONFIG['itw-credential-issuer'].credential_types}`
    );
    expect(ConfigIniTemplate).toContain(`port = ${DEFAULT_CONFIG.rp.port}`);
    expect(ConfigIniTemplate).toContain(`entity_id = ${DEFAULT_CONFIG.rp.entity_id}`);
    expect(ConfigIniTemplate).toContain(`trust_anchor_url = ${DEFAULT_CONFIG.rp.trust_anchor_url}`);
  });

  it('deserializes to DEFAULT_CONFIG', () => {
    expect(ConfigSchema.parse(parse(ConfigIniTemplate))).toEqual(DEFAULT_CONFIG);
  });
});
