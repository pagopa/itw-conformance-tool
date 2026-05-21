import { existsSync, readFileSync } from 'node:fs';

import { describe, it, expect, vi, beforeEach } from 'vitest';

import { printHelp, printVersion } from '../../utils/prompt.js';

describe('printHelp', () => {
  beforeEach(() => {
    vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
  });

  it('writes usage information to stdout', () => {
    printHelp();
    expect(process.stdout.write).toHaveBeenCalled();
    const allOutput = vi
      .mocked(process.stdout.write)
      .mock.calls.map((c) => c[0])
      .join('');
    expect(allOutput).toContain('itw-conformance-tool');
    expect(allOutput).toContain('init');
    expect(allOutput).toContain('start');
    expect(allOutput).toContain('--config');
    expect(allOutput).toContain('--all');
    expect(allOutput).toContain('--issuer');
    expect(allOutput).toContain('--rp');
    expect(allOutput).toContain('--force');
  });
});

describe('printVersion', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
  });

  it('reads and prints the version from package.json', () => {
    vi.mocked(existsSync).mockReturnValue(true);
    vi.mocked(readFileSync).mockReturnValue(JSON.stringify({ version: '1.2.3' }));

    printVersion('/root');

    expect(process.stdout.write).toHaveBeenCalledWith(expect.stringContaining('1.2.3'));
  });

  it('prints "unknown" when package.json does not exist', () => {
    vi.mocked(existsSync).mockReturnValue(false);

    printVersion('/root');

    expect(process.stdout.write).toHaveBeenCalledWith(expect.stringContaining('unknown'));
  });

  it('prints "unknown" when package.json has no version field', () => {
    vi.mocked(existsSync).mockReturnValue(true);
    vi.mocked(readFileSync).mockReturnValue(JSON.stringify({ name: 'itw-conformance-cli' }));

    printVersion('/root');

    expect(process.stdout.write).toHaveBeenCalledWith(expect.stringContaining('unknown'));
  });
});
