#!/usr/bin/env node

import { spawn } from 'node:child_process';
import { closeSync, existsSync, mkdirSync, openSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { resolve } from 'node:path';
import { parseArgs as parseNodeArgs } from 'node:util';

import { loggerOptions as sharedLoggerOptions } from '@itw-conformance-tool/logger';
import pino, { type Logger as PinoLogger, type LoggerOptions } from 'pino';

type Command = 'init' | 'start';
type LogLevel = 'debug' | 'error' | 'info' | 'warn';
type Service = 'issuer' | 'rp';

interface RuntimeConfig {
  dataDir: string;
  issuerPort: number;
  logLevel: LogLevel;
  rpPort: number;
}

interface CliFlags {
  all: boolean;
  configFile?: string;
  dryRun: boolean;
  force: boolean;
  help: boolean;
  issuer: boolean;
  logLevel?: LogLevel;
  rp: boolean;
  skipNxCache: boolean;
  tlsCaFile?: string;
  unsafeTls: boolean;
}

type CliLogger = PinoLogger;

const cliName = 'itw-conformance-tool';
const defaultDataDir = resolve(homedir(), '.itw-conformance-tool');
const defaultRuntimeConfig: RuntimeConfig = {
  dataDir: defaultDataDir,
  issuerPort: 3000,
  logLevel: 'info',
  rpPort: 8080
};

function printHelp(): void {
  process.stdout.write(`\n${cliName} - Local CLI for ITW Conformance Tool\n\n`);
  process.stdout.write('Usage:\n');
  process.stdout.write(`  ${cliName} <command> [options]\n\n`);
  process.stdout.write('Commands:\n');
  process.stdout.write('  init           Initialize local data directory and config template\n');
  process.stdout.write('  start          Start issuer and/or relying party via Nx\n');
  process.stdout.write('  help           Show this help\n\n');
  process.stdout.write('Options:\n');
  process.stdout.write('  -c, --config <path>                 Config path (default: ./config.ini)\n');
  process.stdout.write('  --all                               Start issuer and relying party (default)\n');
  process.stdout.write('  --issuer                            Start only itw-credential-issuer\n');
  process.stdout.write('  --rp                                Start only itw-relying-party\n');
  process.stdout.write('  --force                             Overwrite generated files during init\n');
  process.stdout.write('  --unsafe-tls                        Disable TLS verification for delegated process\n');
  process.stdout.write('  --tls-ca-file <path>                Export CA path as ITW_CT_TLS_CA_FILE\n');
  process.stdout.write('  --log-level <debug|info|warn|error> Log level for CLI logs\n');
  process.stdout.write('  --skip-nx-cache                     Pass --skip-nx-cache to Nx\n');
  process.stdout.write('  --dry-run                           Print action without executing\n');
  process.stdout.write('  -h, --help                          Show help\n\n');
}

function createCliLogger(level: LogLevel): CliLogger {
  const loggerOptions: LoggerOptions = {
    ...sharedLoggerOptions,
    level
  };

  return pino(loggerOptions).child({
    service: 'itw-conformance-cli'
  });
}

function emitLog(logger: CliLogger, level: LogLevel, event: string, details: Record<string, unknown>): void {
  const payload = {
    event,
    ...details
  };

  switch (level) {
    case 'debug':
      logger.debug(payload, event);
      break;
    case 'info':
      logger.info(payload, event);
      break;
    case 'warn':
      logger.warn(payload, event);
      break;
    case 'error':
      logger.error(payload, event);
      break;
  }
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

function parseLogLevel(value: string): LogLevel {
  if (value !== 'debug' && value !== 'info' && value !== 'warn' && value !== 'error') {
    throw new Error(`Invalid log level: ${value}`);
  }
  return value;
}

function parseArgs(argv: string[]): { command?: string; flags: CliFlags } {
  const normalizedArgv = argv.length === 1 && /\s/.test(argv[0]) ? tokenizeArgString(argv[0]) : argv;
  const parsed = parseNodeArgs({
    args: normalizedArgv,
    allowPositionals: true,
    strict: true,
    options: {
      all: { type: 'boolean' },
      config: { type: 'string', short: 'c' },
      'dry-run': { type: 'boolean' },
      force: { type: 'boolean' },
      help: { type: 'boolean', short: 'h' },
      issuer: { type: 'boolean' },
      'log-level': { type: 'string' },
      rp: { type: 'boolean' },
      'skip-nx-cache': { type: 'boolean' },
      'tls-ca-file': { type: 'string' },
      'unsafe-tls': { type: 'boolean' }
    }
  });

  const [command, ...unexpectedPositionals] = parsed.positionals;
  if (unexpectedPositionals.length > 0) {
    throw new Error(`Unexpected positional arguments: ${unexpectedPositionals.join(', ')}`);
  }

  return {
    command,
    flags: {
      all: parsed.values.all ?? false,
      configFile: parsed.values.config,
      dryRun: parsed.values['dry-run'] ?? false,
      force: parsed.values.force ?? false,
      help: parsed.values.help ?? false,
      issuer: parsed.values.issuer ?? false,
      logLevel: parsed.values['log-level'] !== undefined ? parseLogLevel(parsed.values['log-level']) : undefined,
      rp: parsed.values.rp ?? false,
      skipNxCache: parsed.values['skip-nx-cache'] ?? false,
      tlsCaFile: parsed.values['tls-ca-file'],
      unsafeTls: parsed.values['unsafe-tls'] ?? false
    }
  };
}

function isCommand(value: string): value is Command {
  return value === 'init' || value === 'start';
}

function resolveWorkspaceRoot(from: string): string {
  const workspaceRoot = resolve(from);
  const hasNx = existsSync(resolve(workspaceRoot, 'nx.json'));
  const hasPackageJson = existsSync(resolve(workspaceRoot, 'package.json'));

  if (!hasNx || !hasPackageJson) {
    throw new Error('This command must be run from the itw-conformance-tool workspace root');
  }

  return workspaceRoot;
}

function stripIniComment(line: string): string {
  const semicolonIndex = line.indexOf(';');
  const hashIndex = line.indexOf('#');

  if (semicolonIndex === -1 && hashIndex === -1) {
    return line.trim();
  }
  if (semicolonIndex === -1) {
    return line.slice(0, hashIndex).trim();
  }
  if (hashIndex === -1) {
    return line.slice(0, semicolonIndex).trim();
  }
  return line.slice(0, Math.min(semicolonIndex, hashIndex)).trim();
}

function parseIni(iniRaw: string): Record<string, Record<string, string>> {
  const parsedConfig: Record<string, Record<string, string>> = {};
  let currentSection = '';

  for (const rawLine of iniRaw.split(/\r?\n/u)) {
    const line = stripIniComment(rawLine);
    if (line.length === 0) {
      continue;
    }

    if (line.startsWith('[') && line.endsWith(']')) {
      currentSection = line.slice(1, -1).trim().toLowerCase();
      if (currentSection.length > 0 && parsedConfig[currentSection] === undefined) {
        parsedConfig[currentSection] = {};
      }
      continue;
    }

    if (currentSection.length === 0) {
      continue;
    }

    const separatorIndex = line.indexOf('=');
    if (separatorIndex === -1) {
      continue;
    }

    const key = line.slice(0, separatorIndex).trim().toLowerCase();
    const value = line.slice(separatorIndex + 1).trim();
    if (key.length === 0) {
      continue;
    }
    parsedConfig[currentSection] ??= {};
    parsedConfig[currentSection][key] = value;
  }

  return parsedConfig;
}

function expandHome(pathValue: string): string {
  if (pathValue === '~') {
    return homedir();
  }
  if (pathValue.startsWith('~/')) {
    return resolve(homedir(), pathValue.slice(2));
  }
  return resolve(pathValue);
}

function parsePortValue(rawValue: string | undefined, fallback: number, fieldName: string): number {
  if (rawValue === undefined || rawValue.length === 0) {
    return fallback;
  }

  const parsedPort = Number(rawValue);
  if (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65_535) {
    throw new Error(`Invalid ${fieldName} value: ${rawValue}`);
  }

  return parsedPort;
}

function resolveConfigPath(configFile?: string): string {
  return resolve(process.cwd(), configFile ?? 'config.ini');
}

function loadRuntimeConfig(configPath: string, flags: CliFlags): { config: RuntimeConfig; exists: boolean } {
  if (!existsSync(configPath)) {
    return {
      config: {
        ...defaultRuntimeConfig,
        logLevel: flags.logLevel ?? defaultRuntimeConfig.logLevel
      },
      exists: false
    };
  }

  const parsedConfig = parseIni(readFileSync(configPath, { encoding: 'utf8' }));
  const globalSection = parsedConfig.global;
  const issuerSection = parsedConfig['itw-credential-issuer'];
  const rpSection = parsedConfig.rp;

  const dataDirRaw = globalSection?.data_dir;
  const dataDir =
    dataDirRaw !== undefined && dataDirRaw.length > 0 ? expandHome(dataDirRaw) : defaultRuntimeConfig.dataDir;
  const configuredLogLevel = globalSection?.log_level;
  const logLevel =
    flags.logLevel ??
    (configuredLogLevel !== undefined && configuredLogLevel.length > 0
      ? parseLogLevel(configuredLogLevel)
      : defaultRuntimeConfig.logLevel);

  return {
    config: {
      dataDir,
      issuerPort: parsePortValue(issuerSection?.port, defaultRuntimeConfig.issuerPort, '[itw-credential-issuer].port'),
      logLevel,
      rpPort: parsePortValue(rpSection?.port, defaultRuntimeConfig.rpPort, '[rp].port')
    },
    exists: true
  };
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

function buildStartNxArgs(services: Service[], flags: CliFlags): string[] {
  const args =
    services.length === 2
      ? ['nx', 'run-many', '-t', 'serve', '-p', 'itw-credential-issuer,itw-relying-party']
      : ['nx', 'run', services[0] === 'issuer' ? 'itw-credential-issuer:serve' : 'itw-relying-party:serve'];

  if (flags.skipNxCache) {
    args.push('--skip-nx-cache');
  }

  return args;
}

function getConfigIniTemplate(): string {
  return `[global]
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
}

function runInit(configPath: string, runtimeConfig: RuntimeConfig, flags: CliFlags, logger: CliLogger): void {
  const issuerDir = resolve(runtimeConfig.dataDir, 'issuer');
  const rpDir = resolve(runtimeConfig.dataDir, 'rp');

  mkdirSync(runtimeConfig.dataDir, { recursive: true });
  mkdirSync(issuerDir, { recursive: true });
  mkdirSync(rpDir, { recursive: true });

  let configWritten = false;
  if (flags.force) {
    writeFileSync(configPath, getConfigIniTemplate(), { encoding: 'utf8', flag: 'w' });
    configWritten = true;
  } else {
    try {
      const fileDescriptor = openSync(configPath, 'wx');
      try {
        writeFileSync(fileDescriptor, getConfigIniTemplate(), { encoding: 'utf8' });
        configWritten = true;
      } finally {
        closeSync(fileDescriptor);
      }
    } catch (error) {
      const errnoError = error as NodeJS.ErrnoException;
      if (errnoError.code !== 'EEXIST') {
        throw error;
      }
    }
  }

  emitLog(logger, 'info', 'cli.init_summary', {
    configPath,
    configWritten,
    dataDir: runtimeConfig.dataDir,
    force: flags.force,
    issuerDir,
    rpDir
  });
}

function buildEnv(runtimeConfig: RuntimeConfig, configPath: string, flags: CliFlags): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    ITW_CT_CONFIG_FILE: configPath,
    ITW_CT_DATA_DIR: runtimeConfig.dataDir,
    ITW_CT_ISSUER_PORT: String(runtimeConfig.issuerPort),
    ITW_CT_LOG_LEVEL: runtimeConfig.logLevel,
    ITW_CT_RP_PORT: String(runtimeConfig.rpPort),
    ITW_CT_UNSAFE_TLS: flags.unsafeTls ? 'true' : 'false'
  };

  if (flags.tlsCaFile !== undefined) {
    env.ITW_CT_TLS_CA_FILE = flags.tlsCaFile;
  }
  if (flags.unsafeTls) {
    env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  }

  return env;
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
    env,
    stdio: 'inherit'
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

  const configPath = resolveConfigPath(flags.configFile);
  const { config, exists } = loadRuntimeConfig(configPath, flags);
  const logger = createCliLogger(config.logLevel);

  if (command === 'init') {
    if (flags.dryRun) {
      emitLog(logger, 'info', 'cli.dry_run_summary', {
        command,
        configPath,
        dataDir: config.dataDir,
        force: flags.force
      });
      process.exit(0);
    }

    runInit(configPath, config, flags, logger);
    process.exit(0);
  }

  if (!exists) {
    emitLog(logger, 'warn', 'cli.config_not_found_using_defaults', {
      command,
      configPath,
      defaultsApplied: {
        dataDir: config.dataDir,
        issuerPort: config.issuerPort,
        rpPort: config.rpPort
      },
      message: `Configuration file not found: ${configPath}. Starting with defaults. Run '${cliName} init' to generate it.`
    });
  }

  const services = getStartServices(flags);
  const nxArgs = buildStartNxArgs(services, flags);
  const env = buildEnv(config, configPath, flags);

  emitLog(logger, 'debug', 'cli.runtime_config_resolved', {
    command,
    configPath,
    runtimeConfig: config,
    services
  });

  emitLog(logger, 'debug', 'cli.nx_command', {
    command: [process.execPath, resolveLocalNxCli(), ...(nxArgs[0] === 'nx' ? nxArgs.slice(1) : nxArgs)].join(' ')
  });

  if (flags.dryRun) {
    emitLog(logger, 'info', 'cli.dry_run_summary', {
      command,
      configPath,
      nxCommand: ['pnpm', ...nxArgs].join(' '),
      runtimeConfig: config,
      services
    });
    process.exit(0);
  }

  const exitCode = await runCommand(nxArgs, env);

  if (exitCode === 0) {
    emitLog(logger, 'info', 'cli.flow_completed', { command, exitCode, services });
    process.exit(0);
  }

  emitLog(logger, 'error', 'cli.flow_failed', { command, exitCode, services });
  process.exit(exitCode);
}

main().catch((error: unknown) => {
  const logger = createCliLogger('debug');

  if (error instanceof Error) {
    emitLog(logger, 'error', 'cli.unhandled_error', {
      cause: error.cause,
      error,
      message: error.message,
      stack: error.stack
    });
  } else {
    emitLog(logger, 'error', 'cli.unhandled_error', {
      message: String(error),
      thrown: error
    });
  }

  process.exit(1);
});
