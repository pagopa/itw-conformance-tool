import { printHelp, printVersion } from '../utils/prompt.js';
import { expandPath } from '../utils/search.js';

import type { CLIFlags } from '../types/types.js';
import type { Level } from '@itw-conformance-tool/logger';

/** Tokenizes the command-line arguments, handling the case where Nx
 * forwards --args as a single array of strings.
 *
 * @param argv - The array of command-line arguments.
 * @returns An array of tokenized arguments.
 */
function tokenizeArgs(input: string): string[] {
  const args: string[] = [];

  const configRegex = /(?:--config|-c)(?:=|\s+)(?:"([^"]*)"|'([^']*)'|([^\s]+))/;

  const match = configRegex.exec(input);

  let configValue: string | undefined;

  if (match) {
    configValue = match.slice(1).find(Boolean);

    input = input.replace(match[0], '').trim();
  }

  args.push(...input.split(/\s+/).filter(Boolean));

  if (configValue) {
    args.push('--config', configValue);
  }

  return args;
}

/** Extracts the value of the --config flag from the command-line arguments.
 *
 * @param args - The array of command-line arguments.
 * @param i - The current index in the arguments array.
 * @returns An object containing the value of the --config flag and the number of arguments to skip, or null if not found.
 */
function extractConfig(args: string[], i: number): { value: string; skip: number } | null {
  const current = args[i];

  const eqIndex = current.indexOf('=');

  // --config=value or -c=value
  if (eqIndex !== -1) {
    return { value: current.slice(eqIndex + 1), skip: 0 };
  }

  // --config value or -c value
  const next = args[i + 1];

  if (next && !next.startsWith('-')) {
    return { value: next, skip: 1 };
  }

  return null;
}

/** Parses command-line arguments to extract the command and
 * associated flags for the CLI tool.
 *
 * @param argv - The array of command-line arguments.
 * @returns An object containing the parsed command and flags.
 */
export function parseCLIArgs(
  argv: string[],
  rootPath: string,
  emitLog: (event: string, type?: Level | undefined) => void
): { command?: string; flags: CLIFlags } {
  if (argv.length === 0) {
    printHelp();
    throw new Error('No command provided. Please specify a command (init or start) followed by any relevant flags.');
  }

  if (argv.length === 1) {
    argv = tokenizeArgs(argv[0]);
  }

  const command = argv[0].trim().toLowerCase();
  if (['help', '--help', '-h'].includes(command)) {
    printHelp();
    process.exit(0);
  }

  if (['version', '--version', '-v'].includes(command)) {
    printVersion(rootPath);
    process.exit(0);
  }

  if (!(command === 'init' || command === 'start')) {
    throw new Error(`Invalid command: ${command}. Please specify a valid command (init or start).`);
  }

  const flags = {
    issuer: false,
    rp: false,
    all: false,
    force: false,
    config: {
      value: false,
      path: ''
    }
  };

  const args = argv.slice(1);
  for (let i = 0; i < args.length; i++) {
    const raw = args[i];
    const arg = raw.toLowerCase();

    if (arg === '--config' || arg === '-c' || arg.startsWith('--config=') || arg.startsWith('-c=')) {
      const result = extractConfig(args, i);

      if (result?.value) {
        flags.config.value = true;
        flags.config.path = expandPath(result.value.trim(), rootPath);
        i += result.skip;
      }

      continue;
    }

    switch (arg) {
      case '--issuer':
        flags.issuer = true;
        break;

      case '--rp':
        flags.rp = true;
        break;

      case '--all':
      case '-a':
        flags.all = true;
        break;

      case '--force':
      case '-f':
        flags.force = true;
        break;
    }
  }

  return { command, flags };
}
