import { describe, it, expect, vi, beforeEach } from 'vitest';

import { parseCLIArgs } from '../../services/parseCLIArgs.js';
import { expandPath } from '../../utils/path.js';

vi.mock('../../utils/path.js');
vi.mock('../../utils/prompt.js', () => ({
  printHelp: vi.fn(),
  printVersion: vi.fn()
}));

class ProcessExitSignal extends Error {
  constructor(code: number) {
    super(`process.exit(${code})`);
  }
}

const rootPath = '/root';

describe('parseCLIArgs', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(expandPath).mockImplementation((path: string) => `/root/${path}`);
    vi.spyOn(process, 'exit').mockImplementation((code) => {
      throw new ProcessExitSignal((code as number) ?? 0);
    });
  });

  describe('no arguments', () => {
    it('throws when no arguments are provided', () => {
      expect(() => parseCLIArgs([], rootPath)).toThrow(ProcessExitSignal);
    });
  });

  describe('help command', () => {
    it.each([['help'], ['--help'], ['-h']])('calls printHelp and exits for "%s"', async (cmd) => {
      const { printHelp } = await import('../../utils/prompt.js');
      expect(() => parseCLIArgs([cmd], rootPath)).toThrow(ProcessExitSignal);
      expect(printHelp).toHaveBeenCalledOnce();
      expect(process.exit).toHaveBeenCalledWith(0);
    });
  });

  describe('version command', () => {
    it.each([['version'], ['--version'], ['-v']])('calls printVersion and exits for "%s"', async (cmd) => {
      const { printVersion } = await import('../../utils/prompt.js');
      expect(() => parseCLIArgs([cmd], rootPath)).toThrow(ProcessExitSignal);
      expect(printVersion).toHaveBeenCalledWith(rootPath);
      expect(process.exit).toHaveBeenCalledWith(0);
    });
  });

  describe('invalid command', () => {
    it('throws for an unrecognized command', () => {
      expect(() => parseCLIArgs(['unknown'], rootPath)).toThrow(ProcessExitSignal);
    });
  });

  describe('init command', () => {
    it('returns command "init" with default flags', () => {
      const result = parseCLIArgs(['init'], rootPath);
      expect(result.command).toBe('init');
      expect(result.flags).toEqual({
        issuer: false,
        rp: false,
        all: false,
        force: false,
        config: { value: false, path: '' },
        runId: undefined,
        format: 'html'
      });
    });

    it('sets force flag with --force', () => {
      const result = parseCLIArgs(['init', '--force'], rootPath);
      expect(result.flags.force).toBe(true);
    });

    it('sets force flag with -f', () => {
      const result = parseCLIArgs(['init', '-f'], rootPath);
      expect(result.flags.force).toBe(true);
    });
  });

  describe('start command', () => {
    it('returns command "start" with default flags', () => {
      const result = parseCLIArgs(['start'], rootPath);
      expect(result.command).toBe('start');
      expect(result.flags.issuer).toBe(false);
      expect(result.flags.rp).toBe(false);
      expect(result.flags.all).toBe(false);
    });

    it('sets all flag with --all', () => {
      const result = parseCLIArgs(['start', '--all'], rootPath);
      expect(result.flags.all).toBe(true);
    });

    it('sets all flag with -a', () => {
      const result = parseCLIArgs(['start', '-a'], rootPath);
      expect(result.flags.all).toBe(true);
    });

    it('sets issuer flag with --issuer', () => {
      const result = parseCLIArgs(['start', '--issuer'], rootPath);
      expect(result.flags.issuer).toBe(true);
      expect(result.flags.rp).toBe(false);
    });

    it('sets rp flag with --rp', () => {
      const result = parseCLIArgs(['start', '--rp'], rootPath);
      expect(result.flags.rp).toBe(true);
      expect(result.flags.issuer).toBe(false);
    });

    it('sets both issuer and rp flags together', () => {
      const result = parseCLIArgs(['start', '--issuer', '--rp'], rootPath);
      expect(result.flags.issuer).toBe(true);
      expect(result.flags.rp).toBe(true);
    });
  });

  describe('report commands', () => {
    it('parses report:list with --config <path>', () => {
      const result = parseCLIArgs(['report:list', '--config', 'custom.ini'], rootPath);
      expect(result.command).toBe('report:list');
      expect(result.flags.config.value).toBe(true);
      expect(result.flags.config.path).toBe('/root/custom.ini');
    });

    it('parses report:list with -c=<path>', () => {
      const result = parseCLIArgs(['report:list', '-c=custom.ini'], rootPath);
      expect(result.command).toBe('report:list');
      expect(result.flags.config.value).toBe(true);
      expect(result.flags.config.path).toBe('/root/custom.ini');
    });

    it('parses report:create with positional args and --config', () => {
      const result = parseCLIArgs(
        ['report:create', '00000000-0000-0000-0000-000000000000', 'pdf', '--config', 'custom.ini'],
        rootPath
      );
      expect(result.command).toBe('report:create');
      expect(result.flags.runId).toBe('00000000-0000-0000-0000-000000000000');
      expect(result.flags.format).toBe('pdf');
      expect(result.flags.config.value).toBe(true);
      expect(result.flags.config.path).toBe('/root/custom.ini');
    });

    it('parses report:create with --config before positional args', () => {
      const result = parseCLIArgs(
        ['report:create', '--config=custom.ini', '00000000-0000-0000-0000-000000000000', 'html'],
        rootPath
      );
      expect(result.command).toBe('report:create');
      expect(result.flags.runId).toBe('00000000-0000-0000-0000-000000000000');
      expect(result.flags.format).toBe('html');
      expect(result.flags.config.value).toBe(true);
      expect(result.flags.config.path).toBe('/root/custom.ini');
    });
  });

  describe('tokenization of single-argument input', () => {
    it('tokenizes a single "start --all" string', () => {
      const result = parseCLIArgs(['start --all'], rootPath);
      expect(result.command).toBe('start');
      expect(result.flags.all).toBe(true);
    });

    it('tokenizes a single "start --issuer" string', () => {
      const result = parseCLIArgs(['start --issuer'], rootPath);
      expect(result.command).toBe('start');
      expect(result.flags.issuer).toBe(true);
    });

    it('tokenizes a single string containing --config with a value', () => {
      const result = parseCLIArgs(['start --config custom.ini'], rootPath);
      expect(result.command).toBe('start');
      expect(result.flags.config.value).toBe(true);
      expect(result.flags.config.path).toBe('/root/custom.ini');
    });
  });
});
