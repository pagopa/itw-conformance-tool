import { describe, it, expect } from 'vitest';

import { loadRpConfig, deriveBaseUrl, parseIni } from '../config.js';

describe('Config', () => {
  describe('loadRpConfig', () => {
    it('should use default values when no env vars set', async () => {
      const result = await loadRpConfig({ env: {} });

      expect(result.config.host).toBe('localhost');
      expect(result.config.port).toBe(8080);
      expect(result.baseUrl).toBe('http://localhost:8080');
    });

    it('should override from env vars', async () => {
      const result = await loadRpConfig({
        env: {
          ITW_CT_RP_HOST: 'example.com',
          ITW_CT_RP_PORT: '9000',
          ITW_CT_DATA_DIR: '/custom/data'
        }
      });

      expect(result.config.host).toBe('example.com');
      expect(result.config.port).toBe(9000);
      expect(result.config.dataDir).toBe('/custom/data');
      expect(result.baseUrl).toBe('http://example.com:9000');
    });

    it('should use custom base URL if provided', async () => {
      const result = await loadRpConfig({
        env: {
          ITW_CT_RP_BASE_URL: 'https://custom.example.com'
        }
      });

      expect(result.baseUrl).toBe('https://custom.example.com');
    });
  });

  describe('deriveBaseUrl', () => {
    it('should derive base URL from host and port', () => {
      const url = deriveBaseUrl('localhost', 8080);
      expect(url).toBe('http://localhost:8080');
    });

    it('should work with different host and port', () => {
      const url = deriveBaseUrl('rp.example.com', 3000);
      expect(url).toBe('http://rp.example.com:3000');
    });
  });

  describe('parseIni', () => {
    it('should parse simple ini format', () => {
      const ini = `[rp]
host=localhost
port=8080

[issuer]
url=http://issuer.example.com`;

      const result = parseIni(ini);

      expect(result.rp).toEqual({ host: 'localhost', port: '8080' });
      expect(result.issuer).toEqual({ url: 'http://issuer.example.com' });
    });

    it('should ignore comments and empty lines', () => {
      const ini = `; This is a comment
[rp]
; Another comment
host=localhost

port=8080`;

      const result = parseIni(ini);

      expect(result.rp).toEqual({ host: 'localhost', port: '8080' });
    });

    it('should handle values with equals signs', () => {
      const ini = `[section]
key=value=with=equals`;

      const result = parseIni(ini);

      expect(result.section.key).toBe('value=with=equals');
    });
  });
});
