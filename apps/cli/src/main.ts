import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import path, { resolve } from 'node:path';
import { parseArgs as parseNodeArgs } from 'node:util';

import { parseINI, type ConfigType } from '@itw-conformance-tool/config';
import { loggerOptions as sharedLoggerOptions } from '@itw-conformance-tool/logger';
import pino, { type Logger as PinoLogger, type LoggerOptions } from 'pino';

type Service = 'issuer' | 'rp';
type Command = 'init' | 'start';

interface CliFlags {
  configFile?: string;
  all?: boolean;
  issuer?: boolean;
  rp?: boolean;
  force?: boolean;
  help: boolean;
}

const cliName = 'itw-conformance-tool';

const serviceToProject: Record<Service, string> = {
  issuer: 'itw-credential-issuer',
  rp: 'itw-relying-party'
};

const configIniTemplate = `[global]
; Local directory for keys, certificates, and generated data
; Default: ~/.itw-conformance-tool
data_dir = ~/.itw-conformance-tool
; Logging level: debug | info | warn | error
; Default: info
log_level = info

[itw-credential-issuer]
; HTTP port for the issuer service
; Default: 3000
port = 3000
; Enabled credential types: pid | mdl | badge | eaa (comma-separated)
; Default: pid,mdl,badge,eaa
credential_types = pid,mdl,badge,eaa

[rp]
; HTTP port for the itw-relying-party service
; Default: 8080
port = 8080
`;

type CliLogger = PinoLogger;
type LogLevel = 'fatal' | 'error' | 'warn' | 'info' | 'debug' | 'trace';

function printHelp(): void {
  process.stdout.write(`\n${cliName} - Local CLI for ITW Conformance flows\n\n`);
  process.stdout.write('Usage:\n');
  process.stdout.write(`  ${cliName} <command> [options]\n\n`);
  process.stdout.write('Commands:\n');
  process.stdout.write('  init           Initialize local workspace assets (data directory + config.ini template)\n');
  process.stdout.write('  start          Start local services via Nx\n');
  process.stdout.write('  help           Show this help\n\n');
  process.stdout.write('Options:\n');
  process.stdout.write('  -c, --config <path>                Config path (for init output and runtime overrides)\n');
  process.stdout.write('  --all                              Start issuer and relying party (default for start)\n');
  process.stdout.write('  --issuer                           Start only itw-credential-issuer\n');
  process.stdout.write('  --rp                               Start only itw-relying-party\n');
  process.stdout.write('  --force                            Force overwrite for init-generated files\n');
  process.stdout.write('  -h, --help                         Show help\n\n');
  process.stdout.write('Examples:\n');
  process.stdout.write(`  ${cliName} init --force\n`);
  process.stdout.write(`  ${cliName} start --all\n`);
  process.stdout.write(`  ${cliName} start --issuer\n\n`);
}

function createCliLogger(logLevel: LogLevel): CliLogger {
  const loggerOptions: LoggerOptions = {
    ...sharedLoggerOptions,
    level: logLevel
  };

  return pino(loggerOptions).child({
    service: 'itw-conformance-cli'
  });
}

function emitLog(logger: CliLogger, event: string, details: Record<string, unknown>, type: LogLevel = 'debug'): void {
  const payload = {
    event,
    ...details
  };

  logger[type](payload, event);
}

function tokenizeArgString(argsString: string): string[] {
  const tokens: string[] = [];
  let current = '';
  let quote: '"' | "'" | undefined;

  for (let index = 0; index < argsString.length; index += 1) {
    const char = argsString[index];

    if (quote !== undefined) {
      if (char === '\\' && index + 1 < argsString.length) {
        current += argsString[index + 1];
        index += 1;
        continue;
      }

      if (char === quote) {
        quote = undefined;
        continue;
      }

      current += char;
      continue;
    }

    if (char === '"' || char === "'") {
      quote = char;
      continue;
    }

    if (/\s/.test(char)) {
      if (current.length > 0) {
        tokens.push(current);
        current = '';
      }
      continue;
    }

    current += char;
  }

  if (quote !== undefined) {
    throw new Error('Invalid --args payload: unmatched quote');
  }

  if (current.length > 0) {
    tokens.push(current);
  }

  return tokens;
}

function parseArgs(argv: string[]): { command?: string; flags: CliFlags } {
  const normalizedArgv = argv.length === 1 && /\s/.test(argv[0]) ? tokenizeArgString(argv[0]) : argv;
  const parsed = parseNodeArgs({
    args: normalizedArgv,
    allowPositionals: true,
    strict: true,
    options: {
      help: {
        type: 'boolean',
        short: 'h'
      },
      all: {
        type: 'boolean'
      },
      issuer: {
        type: 'boolean'
      },
      rp: {
        type: 'boolean'
      },
      force: {
        type: 'boolean'
      },
      config: {
        type: 'string',
        short: 'c'
      }
    }
  });

  const [command, ...unexpectedPositionals] = parsed.positionals;
  if (unexpectedPositionals.length > 0) {
    throw new Error(`Unexpected positional arguments: ${unexpectedPositionals.join(', ')}`);
  }

  const flags: CliFlags = {
    help: parsed.values.help ?? false
  };

  if (parsed.values.all) {
    flags.all = true;
  }
  if (parsed.values.issuer) {
    flags.issuer = true;
  }
  if (parsed.values.rp) {
    flags.rp = true;
  }
  if (parsed.values.force) {
    flags.force = true;
  }
  if (parsed.values.config !== undefined) {
    flags.configFile = parsed.values.config.trim();
  }

  return { command, flags };
}

function isCommand(value: string): value is Command {
  return value === 'init' || value === 'start';
}

function resolveWorkspaceRoot(from: string): string {
  const workspaceRoot = resolve(from);
  const hasNx = existsSync(resolve(workspaceRoot, 'nx.json'));
  const hasPackage = existsSync(resolve(workspaceRoot, 'package.json'));

  if (!hasNx || !hasPackage) {
    throw new Error('This command must be run from the itw-conformance-tool workspace root');
  }

  return workspaceRoot;
}

function getStartServices(flags: CliFlags): Service[] {
  const selectedServices: Service[] = [];

  if (flags.issuer) {
    selectedServices.push('issuer');
  }
  if (flags.rp) {
    selectedServices.push('rp');
  }

  if (flags.all || selectedServices.length === 0) {
    return ['issuer', 'rp'];
  }

  return selectedServices;
}

function buildStartNxArgs(services: Service[]): string[] {
  const args =
    services.length === 2
      ? ['nx', 'run-many', '-t', 'serve', '-p', `${serviceToProject.issuer},${serviceToProject.rp}`]
      : ['nx', 'run', `${serviceToProject[services[0]]}:serve`];

  return args;
}

function runInit(flags: CliFlags, configFilePath: string): void {
  const dataDir = resolve(homedir(), '.itw-conformance-tool');
  const issuerDir = resolve(dataDir, 'issuer');
  const rpDir = resolve(dataDir, 'rp');

  mkdirSync(issuerDir, { recursive: true });
  mkdirSync(rpDir, { recursive: true });

  const configFileExists = existsSync(configFilePath);
  if (flags.force || !configFileExists) {
    configFilePath = resolve(process.cwd(), 'config.ini');
    writeFileSync(configFilePath, configIniTemplate, { encoding: 'utf8', flag: 'w' });
  }

  const logger = createCliLogger('debug');
  emitLog(logger, 'cli.init_summary', {
    dataDir,
    issuerDir,
    rpDir,
    configFilePath,
    configGenerated: flags.force || !configFileExists,
    force: flags.force
  });
}

function buildEnv(config: ConfigType): NodeJS.ProcessEnv {
  return {
    ...process.env,
    ITW_CT_LOG_LEVEL: config.global.log_level,
    ITW_CT_ISSUER_PORT: String(config['itw-credential-issuer'].port),
    ITW_CT_ISSUER_CREDENTIAL_TYPES: String(config['itw-credential-issuer'].credential_types),
    ITW_CT_RP_PORT: String(config.rp.port)
  };
}

function resolveLocalNxCli(): string {
  const candidatePaths = [
    resolve(process.cwd(), 'node_modules', 'nx', 'bin', 'nx.js'),
    resolve(process.cwd(), 'node_modules', 'nx', 'dist', 'bin', 'nx.js')
  ];

  for (const candidatePath of candidatePaths) {
    if (existsSync(candidatePath)) {
      return candidatePath;
    }
  }

  throw new Error('Unable to locate the local Nx CLI in node_modules');
}

async function runCommand(args: string[], env: NodeJS.ProcessEnv): Promise<number> {
  const nxCliPath = resolveLocalNxCli();
  const nxArgs = args[0] === 'nx' ? args.slice(1) : args;
  const child = spawn(process.execPath, [nxCliPath, ...nxArgs], {
    stdio: 'inherit',
    env
  });

  return new Promise<number>((resolveExitCode, reject) => {
    child.once('error', reject);
    child.once('close', (code) => {
      resolveExitCode(code ?? 1);
    });
  });
}

async function main(): Promise<void> {
  const { command, flags } = parseArgs(process.argv.slice(2));

  if (flags.help || command === 'help') {
    printHelp();
    process.exit(0);
  }

  if (command === undefined) {
    printHelp();
    process.exit(1);
  }

  if (!isCommand(command)) {
    throw new Error(`Unknown command: ${command}`);
  }

  resolveWorkspaceRoot(process.cwd());

  let configFilePath: string;
  if ('configFile' in flags && typeof flags.configFile === 'string' && !flags.force) {
    configFilePath = path.resolve(flags.configFile);
  } else {
    configFilePath = path.resolve(process.cwd(), 'config.ini');
  }

  if (command === 'init') {
    runInit(flags, configFilePath);
    process.exit(0);
  }

  const isINIparsed = parseINI(configFilePath);
  const configs = isINIparsed.data;

  const logger = createCliLogger(configs.global.log_level);

  emitLog(
    logger,
    'cli.runtime_config_resolved',
    {
      command,
      flags,
      configs
    },
    'debug'
  );

  const services = getStartServices(flags);
  const nxArgs = buildStartNxArgs(services);

  emitLog(
    logger,
    'cli.nx_command',
    {
      command,
      services,
      nxCommand: ['pnpm', ...nxArgs].join(' ')
    },
    'debug'
  );

  const env = buildEnv(configs);

  const exitCode = await runCommand(nxArgs, env);
  if (exitCode === 0) {
    emitLog(logger, 'cli.flow_completed', { command, services, exitCode });
    process.exit(0);
  }

  emitLog(logger, 'cli.flow_failed', { command, services, exitCode }, 'error');
  process.exit(exitCode);
}

main().catch((error: unknown) => {
  const logger = createCliLogger('trace');

  if (error instanceof Error) {
    emitLog(
      logger,
      'cli.unhandled_error',
      {
        message: error.message,
        error,
        stack: error.stack,
        cause: error.cause
      },
      'error'
    );
  } else {
    emitLog(
      logger,
      'cli.unhandled_error',
      {
        message: String(error),
        thrown: error
      },
      'error'
    );
  }

  process.exit(1);
});
