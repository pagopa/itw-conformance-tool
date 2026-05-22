import { existsSync, statSync } from 'node:fs';

import { describe, it, expect, vi, beforeEach } from 'vitest';

import { findRoot, searchNx, expandPath, createFileDirPaths, existsFileSync } from '../../utils/search.js';

describe('findRoot', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns the start directory if nx.json is present there', () => {
    vi.mocked(existsSync).mockImplementation((p) => String(p).endsWith('nx.json'));
    const result = findRoot('/some/workspace');
    expect(result).toBe('/some/workspace');
  });

  it('traverses up directories until nx.json is found', () => {
    vi.mocked(existsSync).mockImplementation((p) => {
      return String(p) === '/some/nx.json';
    });

    const result = findRoot('/some/workspace/apps/cli');
    expect(result).toBe('/some');
  });

  it('throws when nx.json is not found in any ancestor directory', () => {
    vi.mocked(existsSync).mockReturnValue(false);
    expect(() => findRoot('/some/workspace')).toThrow('Could not find the root of the Nx workspace');
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

describe('expandPath', () => {
  it('replaces leading ~ with the root path', () => {
    const result = expandPath('~/.itw-conformance-tool', '/root');
    expect(result).toBe('/root/.itw-conformance-tool');
  });

  it('strips surrounding double quotes before expanding', () => {
    const result = expandPath('"config/my config.ini"', '/root');
    expect(result).toBe('/root/config/my config.ini');
  });

  it('strips surrounding single quotes before expanding', () => {
    const result = expandPath("'config/my config.ini'", '/root');
    expect(result).toBe('/root/config/my config.ini');
  });

  it('resolves a relative path against rootPath', () => {
    const result = expandPath('config.ini', '/root');
    expect(result).toBe('/root/config.ini');
  });

  it('returns an absolute path unchanged', () => {
    const result = expandPath('/absolute/path/config.ini', '/root');
    expect(result).toBe('/absolute/path/config.ini');
  });
});

describe('createFileDirPaths', () => {
  it('returns the expected five file paths', () => {
    const paths = createFileDirPaths('/data');
    expect(paths).toHaveLength(5);
    expect(paths).toContain('/data/issuer/signing-keys.jwks.json');
    expect(paths).toContain('/data/issuer/iaca-cert.pem');
    expect(paths).toContain('/data/issuer/iaca-key.pem');
    expect(paths).toContain('/data/rp/auth-request-key.jwk.json');
    expect(paths).toContain('/data/rp/auth-response-key.jwk.json');
  });
});

describe('existsFileSync', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns true when the path exists and is a file', () => {
    vi.mocked(existsSync).mockReturnValue(true);
    vi.mocked(statSync).mockReturnValue({ isFile: () => true } as ReturnType<typeof statSync>);

    expect(existsFileSync('/some/file.json')).toBe(true);
  });

  it('returns false when the path does not exist', () => {
    vi.mocked(existsSync).mockReturnValue(false);

    expect(existsFileSync('/missing/file.json')).toBe(false);
    expect(statSync).not.toHaveBeenCalled();
  });

  it('returns false when the path exists but is a directory', () => {
    vi.mocked(existsSync).mockReturnValue(true);
    vi.mocked(statSync).mockReturnValue({ isFile: () => false } as ReturnType<typeof statSync>);

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
