import { expandPath } from '../utils/path.js';
import { printHelp, printVersion } from '../utils/prompt.js';
import { searchParamValue } from '../utils/search.js';

import type { CliFlags } from '../types/types.js';

/** Parses start command flags.
 *
 * @param args - The array of command-line arguments.
 * @param flags - The flags object to populate.
 * @returns void
 */
function parseStartFlags(args: string[], flags: CliFlags): void {
  const configResult = searchParamValue('--config', args) ?? searchParamValue('-c', args);
  if (configResult) {
    flags.config.value = true;
    flags.config.path = expandPath(configResult.value.trim());
    args = configResult.remainingArgs;
  }

  for (const raw of args) {
    const arg = raw.toLowerCase();
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
      default:
        throw new Error(
          `Invalid flag for start command: ${raw}. ` + `Allowed flags are: --all/-a, --rp, --issuer, --config/-c`
        );
    }
  }
}

/** Parses init command flags.
 *
 * @param args - The array of command-line arguments.
 * @param flags - The flags object to populate.
 * @returns void
 */
function parseInitFlags(args: string[], flags: CliFlags): void {
  for (const arg of args) {
    const lowerArg = arg.toLowerCase();
    if (lowerArg === '--force' || lowerArg === '-f') {
      flags.force = true;
    } else {
      throw new Error(`Invalid flag for init command: ${arg}. Only --force is allowed.`);
    }
  }
}

/** Parses report:list command flags.
 *
 * @param args - The array of command-line arguments.
 * @param flags - The flags object to populate.
 * @returns void
 */
function parseReportListFlags(args: string[], flags: CliFlags): void {
  const configResult = searchParamValue('--config', args) ?? searchParamValue('-c', args);
  if (configResult) {
    flags.config.value = true;
    flags.config.path = expandPath(configResult.value.trim());
    args = configResult.remainingArgs;
  }

  if (args.length > 0) {
    throw new Error(`Invalid argument for report:list: ${args[0]}. Allowed flag is: --config/-c`);
  }
}

/** Parses report:create command flags.
 *
 * @param args - The array of command-line arguments.
 * @param flags - The flags object to populate.
 * @returns void
 */
function parseReportCreateFlags(args: string[], flags: CliFlags): void {
  const configResult = searchParamValue('--config', args) ?? searchParamValue('-c', args);
  if (configResult) {
    flags.config.value = true;
    flags.config.path = expandPath(configResult.value.trim());
    args = configResult.remainingArgs;
  }

  const positionalArgs = args;
  if (positionalArgs.length === 0) {
    throw new Error('report:create requires at least one argument: <uuid> [format_to_print]');
  }

  flags.runId = positionalArgs[0];
  const format = positionalArgs[1]?.toLowerCase();
  if (format === 'html' || format === 'pdf') {
    flags.format = format;
  } else if (format !== undefined) {
    throw new Error(`Invalid format: ${format}. Must be 'html' or 'pdf'.`);
  }

  if (positionalArgs.length > 2) {
    throw new Error('report:create accepts only two arguments: uuid and format_to_print');
  }
}

/** Parses test command flags.
 *
 * @param args - The array of command-line arguments.
 * @param flags - The flags object to populate.
 * @returns void
 */
function parseTestFlags(args: string[], flags: CliFlags): void {
  const configResult = searchParamValue('--config', args) ?? searchParamValue('-c', args);
  if (configResult) {
    flags.config.value = true;
    flags.config.path = expandPath(configResult.value.trim());
    args = configResult.remainingArgs;
  }

  if (args.length > 0) {
    throw new Error(`Invalid argument for test command: ${args[0]}. Allowed flags are: --config/-c`);
  }
}

/** Parses command-line arguments to extract the command and
 * associated flags for the CLI tool.
 *
 * @param argv - The array of command-line arguments.
 * @returns An object containing the parsed command and flags.
 */
export function parseCliArgs(argv: string[], rootPath: string): { command: string; flags: CliFlags } {
  if (argv.length === 0) {
    process.stdout.write(`No command provided. These are the available commands:\n`);
    printHelp();
    process.exit(1);
  }

  if (argv.length === 1) {
    argv = argv[0]
      .split(/\s+/)
      .map((arg) => arg.trim())
      .filter(Boolean);
  }

  const command = argv[0].trim().toLowerCase();
  const validCommands = [
    'init',
    'start',
    'test',
    'report:list',
    'report:create',
    'help',
    '--help',
    '-h',
    'version',
    '--version',
    '-v'
  ];
  if (!validCommands.includes(command)) {
    process.stdout.write(`Invalid command: ${command}\n`);
    printHelp();
    process.exit(1);
  }

  const flags: CliFlags = {
    issuer: false,
    rp: false,
    all: false,
    force: false,
    config: {
      value: false,
      path: ''
    },
    runId: undefined,
    format: 'html'
  };

  const args = argv.slice(1);
  switch (command) {
    case 'init':
      parseInitFlags(args, flags);
      break;
    case 'start':
      parseStartFlags(args, flags);
      break;
    case 'test': {
      parseTestFlags(args, flags);
      break;
    }
    case 'report:list':
      parseReportListFlags(args, flags);
      break;
    case 'report:create':
      parseReportCreateFlags(args, flags);
      break;
    case 'help':
    case '--help':
    case '-h':
      if (args.length > 0) {
        process.stdout.write('Help command does not accept any flags or arguments\n');
      }
      printHelp();
      process.exit(0);
      break;
    case 'version':
    case '--version':
    case '-v':
      if (args.length > 0) {
        process.stdout.write('Version command does not accept any flags or arguments\n');
      }
      printVersion(rootPath);
      process.exit(0);
      break;
    default:
      process.stdout.write(`Unknown command: ${command}\n`);
      printHelp();
      process.exit(1);
      break;
  }

  return { command, flags };
}
