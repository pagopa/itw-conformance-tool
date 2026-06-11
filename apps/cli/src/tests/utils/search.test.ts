import { existsSync, statSync } from 'node:fs';

import { describe, it, expect, vi, beforeEach } from 'vitest';

import { findNxRoot, searchNx, filesToSearch, existsFileSync } from '../../utils/search.js';

describe('findNxRoot', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns the start directory if nx.json is present there', () => {
    vi.mocked(existsSync).mockImplementation((p) => String(p).endsWith('nx.json'));
    const result = findNxRoot('/some/workspace');
    expect(result).toBe('/some/workspace');
  });

  it('traverses up directories until nx.json is found', () => {
    vi.mocked(existsSync).mockImplementation((p) => {
      return String(p) === '/some/nx.json';
    });

    const result = findNxRoot('/some/workspace/apps/cli');
    expect(result).toBe('/some');
  });

  it('throws when nx.json is not found in any ancestor directory', () => {
    vi.mocked(existsSync).mockReturnValue(false);
    expect(() => findNxRoot('/some/workspace')).toThrow('Could not find the root of the Nx workspace');
  });
});

describe('searchNx', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns the first matching nx path', () => {
    vi.mocked(existsSync).mockImplementation((p) => String(p).includes('node_modules/nx/dist/bin/nx.js'));

    const result = searchNx('/root');
    expect(result).toBe('/root/node_modules/nx/dist/bin/nx.js');
  });

  it('falls back to the second candidate path if the first is missing', () => {
    vi.mocked(existsSync).mockImplementation((p) => String(p).includes('apps/cli/node_modules/nx/dist/bin/nx.js'));

    const result = searchNx('/root');
    expect(result).toBe('/root/apps/cli/node_modules/nx/dist/bin/nx.js');
  });

  it('throws when no nx binary is found', () => {
    vi.mocked(existsSync).mockReturnValue(false);
    expect(() => searchNx('/root')).toThrow('Unable to locate the local Nx CLI in node_modules');
  });
});

describe('filesToSearch', () => {
  it('returns the expected six file paths when HTTPS is disabled', () => {
    const paths = filesToSearch('/data');
    expect(paths).toHaveLength(6);
    expect(paths).toContain('/data/issuer/signing-keys.jwks.json');
    expect(paths).toContain('/data/issuer/iaca-cert.pem');
    expect(paths).toContain('/data/issuer/iaca-key.pem');
    expect(paths).toContain('/data/rp/auth-request-key.jwk.json');
    expect(paths).toContain('/data/rp/auth-response-key.jwk.json');
    expect(paths).toContain('/data/rp/x5c-cert.pem');
  });

  it('returns eight file paths when HTTPS is enabled', () => {
    const paths = filesToSearch('/data', true);
    expect(paths).toHaveLength(8);
    expect(paths).toContain('/data/issuer/signing-keys.jwks.json');
    expect(paths).toContain('/data/issuer/iaca-cert.pem');
    expect(paths).toContain('/data/issuer/iaca-key.pem');
    expect(paths).toContain('/data/rp/auth-request-key.jwk.json');
    expect(paths).toContain('/data/rp/auth-response-key.jwk.json');
    expect(paths).toContain('/data/rp/x5c-cert.pem');
    expect(paths).toContain('/data/tls-cert.pem');
    expect(paths).toContain('/data/tls-key.pem');
  });

  it('does not include TLS paths when httpsEnabled is explicitly false', () => {
    const paths = filesToSearch('/data', false);
    expect(paths).toHaveLength(6);
    expect(paths).not.toContain('/data/tls-cert.pem');
    expect(paths).not.toContain('/data/tls-key.pem');
  });
});

describe('existsFileSync', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns true when the path exists and is a file', () => {
    vi.mocked(existsSync).mockReturnValue(true);
    vi.mocked(statSync).mockReturnValue({ isFile: () => true });

    expect(existsFileSync('/some/file.json')).toBe(true);
  });

  it('returns false when the path does not exist', () => {
    vi.mocked(existsSync).mockReturnValue(false);

    expect(existsFileSync('/missing/file.json')).toBe(false);
    expect(statSync).not.toHaveBeenCalled();
  });

  it('returns false when the path exists but is a directory', () => {
    vi.mocked(existsSync).mockReturnValue(true);
    vi.mocked(statSync).mockReturnValue({ isFile: () => false });

    expect(existsFileSync('/some/directory')).toBe(false);
  });

  it('returns false when statSync throws', () => {
    vi.mocked(existsSync).mockReturnValue(true);
    vi.mocked(statSync).mockImplementation(() => {
      throw new Error('Permission denied');
    });

    expect(existsFileSync('/restricted/file.json')).toBe(false);
  });
});
