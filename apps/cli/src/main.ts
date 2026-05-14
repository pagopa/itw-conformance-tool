import { spawn } from 'node:child_process';
import { closeSync, existsSync, mkdirSync, openSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { resolve } from 'node:path';
import { parseArgs as parseNodeArgs } from 'node:util';

import { loggerOptions as sharedLoggerOptions } from '@itw-conformance-tool/logger';
import pino, { type Logger as PinoLogger, type LoggerOptions } from 'pino';

type LogLevel = 'debug' | 'info' | 'warn' | 'error';
type Service = 'issuer' | 'rp';
type Command = 'init' | 'start';

interface TlsConfig {
  unsafe: boolean;
  caFile?: string;
}

interface NxConfig {
  skipCache: boolean;
  extraArgs: string[];
}

interface RuntimeConfig {
  logLevel: LogLevel;
  tls: TlsConfig;
  nx: NxConfig;
}

interface NormalizedRuntimeConfig {
  logLevel?: RuntimeConfig['logLevel'];
  tls?: Partial<TlsConfig>;
  nx?: Partial<NxConfig>;
}

interface CliFlags {
  configFile?: string;
  logLevel?: LogLevel;
  unsafeTls?: boolean;
  tlsCaFile?: string;
  skipNxCache?: boolean;
  all?: boolean;
  issuer?: boolean;
  rp?: boolean;
  force?: boolean;
  dryRun: boolean;
  help: boolean;
}

interface StartServicePorts {
  issuer: number;
  rp: number;
}

const cliName = 'itw-conformance-tool';

const defaultConfig: RuntimeConfig = {
  logLevel: 'info',
  tls: {
    unsafe: false
  },
  nx: {
    skipCache: false,
    extraArgs: []
  }
};

const serviceToProject: Record<Service, string> = {
  issuer: 'itw-credential-issuer',
  rp: 'itw-relying-party'
};

type CliLogger = PinoLogger;

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
  process.stdout.write('  --unsafe-tls                       Disable TLS certificate verification\n');
  process.stdout.write('  --tls-ca-file <path>               Export CA file path as ITW_CT_TLS_CA_FILE\n');
  process.stdout.write('  --log-level <debug|info|warn|error> Log level for CLI logs\n');
  process.stdout.write('  --skip-nx-cache                    Pass --skip-nx-cache to Nx\n');
  process.stdout.write('  --dry-run                          Print computed action and stop\n');
  process.stdout.write('  -h, --help                         Show help\n\n');
  process.stdout.write('Examples:\n');
  process.stdout.write(`  ${cliName} init --force\n`);
  process.stdout.write(`  ${cliName} start --all\n`);
  process.stdout.write(`  ${cliName} start --issuer\n\n`);
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
      'dry-run': {
        type: 'boolean'
      },
      'unsafe-tls': {
        type: 'boolean'
      },
      'skip-nx-cache': {
        type: 'boolean'
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
      },
      'log-level': {
        type: 'string'
      },
      'tls-ca-file': {
        type: 'string'
      }
    }
  });

  const [command, ...unexpectedPositionals] = parsed.positionals;
  if (unexpectedPositionals.length > 0) {
    throw new Error(`Unexpected positional arguments: ${unexpectedPositionals.join(', ')}`);
  }

  const flags: CliFlags = {
    dryRun: parsed.values['dry-run'] ?? false,
    help: parsed.values.help ?? false
  };

  if (parsed.values['unsafe-tls']) {
    flags.unsafeTls = true;
  }
  if (parsed.values['skip-nx-cache']) {
    flags.skipNxCache = true;
  }
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
    flags.configFile = parsed.values.config;
  }

  if (parsed.values['log-level'] !== undefined) {
    const logLevel = parsed.values['log-level'];
    if (!isLogLevel(logLevel)) {
      throw new Error(`Invalid log level: ${logLevel}`);
    }
    flags.logLevel = logLevel;
  }

  if (parsed.values['tls-ca-file'] !== undefined) {
    flags.tlsCaFile = parsed.values['tls-ca-file'];
  }

  return { command, flags };
}

function isLogLevel(value: string): value is LogLevel {
  return value === 'debug' || value === 'info' || value === 'warn' || value === 'error';
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

function normalizeRawConfig(): NormalizedRuntimeConfig {
  return {};
}

function mergeConfig(fileConfig: NormalizedRuntimeConfig, flags: CliFlags): RuntimeConfig {
  return {
    logLevel: flags.logLevel ?? fileConfig.logLevel ?? defaultConfig.logLevel,
    tls: {
      unsafe: flags.unsafeTls ?? fileConfig.tls?.unsafe ?? defaultConfig.tls.unsafe,
      caFile: flags.tlsCaFile ?? fileConfig.tls?.caFile ?? defaultConfig.tls.caFile
    },
    nx: {
      skipCache: flags.skipNxCache ?? fileConfig.nx?.skipCache ?? defaultConfig.nx.skipCache,
      extraArgs: fileConfig.nx?.extraArgs ?? defaultConfig.nx.extraArgs
    }
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

function buildStartNxArgs(services: Service[], runtimeConfig: RuntimeConfig): string[] {
  const args =
    services.length === 2
      ? ['nx', 'run-many', '-t', 'serve', '-p', `${serviceToProject.issuer},${serviceToProject.rp}`]
      : ['nx', 'run', `${serviceToProject[services[0]]}:serve`];

  if (runtimeConfig.nx.skipCache) {
    args.push('--skip-nx-cache');
  }

  if (runtimeConfig.nx.extraArgs.length > 0) {
    args.push(...runtimeConfig.nx.extraArgs);
  }

  return args;
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

function parseIni(rawConfig: string): Record<string, Record<string, string>> {
  const parsedConfig: Record<string, Record<string, string>> = {};
  let currentSection = '';

  for (const rawLine of rawConfig.split(/\r?\n/u)) {
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

function parsePortValue(rawValue: string | undefined, fallback: number, fieldName: string): number {
  if (rawValue === undefined || rawValue.length === 0) {
    return fallback;
  }

  const parsedPort = Number(rawValue);
  if (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
    throw new Error(`Invalid ${fieldName} value: ${rawValue}`);
  }

  return parsedPort;
}

function resolveConfigPath(configFile?: string): string {
  return resolve(process.cwd(), configFile ?? 'config.ini');
}

function resolveServicePorts(configPath: string): StartServicePorts {
  if (!existsSync(configPath)) {
    return {
      issuer: 3000,
      rp: 8080
    };
  }

  const parsedConfig = parseIni(readFileSync(configPath, { encoding: 'utf8' }));

  return {
    issuer: parsePortValue(parsedConfig['itw-credential-issuer']?.port, 3000, '[itw-credential-issuer].port'),
    rp: parsePortValue(parsedConfig.rp?.port, 8080, '[rp].port')
  };
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

function runInit(flags: CliFlags, logger: CliLogger): void {
  const dataDir = resolve(homedir(), '.itw-conformance-tool');
  const issuerDir = resolve(dataDir, 'issuer');
  const rpDir = resolve(dataDir, 'rp');
  const configPath = resolve(process.cwd(), flags.configFile ?? 'config.example.ini');

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
    dataDir,
    issuerDir,
    rpDir,
    configPath,
    configWritten,
    force: Boolean(flags.force)
  });
}

function buildEnv(runtimeConfig: RuntimeConfig, configPath: string, servicePorts: StartServicePorts): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    ITW_CT_LOG_LEVEL: runtimeConfig.logLevel,
    ITW_CT_UNSAFE_TLS: runtimeConfig.tls.unsafe ? 'true' : 'false',
    ITW_CT_CONFIG_FILE: configPath,
    ITW_CT_ISSUER_PORT: String(servicePorts.issuer),
    ITW_CT_RP_PORT: String(servicePorts.rp)
  };

  if (runtimeConfig.tls.caFile !== undefined) {
    env.ITW_CT_TLS_CA_FILE = runtimeConfig.tls.caFile;
  }
  if (runtimeConfig.tls.unsafe) {
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
  const fileConfig = normalizeRawConfig();
  const runtimeConfig = mergeConfig(fileConfig, flags);
  const logger = createCliLogger(runtimeConfig.logLevel);

  emitLog(logger, 'debug', 'cli.runtime_config_resolved', {
    command,
    flags,
    runtimeConfig
  });

  if (command === 'init') {
    if (flags.dryRun) {
      const configPath = resolve(process.cwd(), flags.configFile ?? 'config.example.ini');
      emitLog(logger, 'info', 'cli.dry_run_summary', {
        command,
        dataDir: resolve(homedir(), '.itw-conformance-tool'),
        configPath,
        force: Boolean(flags.force)
      });
      process.exit(0);
    }

    runInit(flags, logger);
    process.exit(0);
  }

  const runtimeConfigPath = resolveConfigPath(flags.configFile);
  const servicePorts = resolveServicePorts(runtimeConfigPath);
  if (!existsSync(runtimeConfigPath)) {
    emitLog(logger, 'warn', 'cli.config_not_found_using_defaults', {
      command,
      configPath: runtimeConfigPath,
      defaultsApplied: {
        issuerPort: servicePorts.issuer,
        rpPort: servicePorts.rp
      },
      message: `Configuration file not found: ${runtimeConfigPath}. Starting with defaults. Run '${cliName} init' to generate a template.`
    });
  }

  const services = getStartServices(flags);
  const nxArgs = buildStartNxArgs(services, runtimeConfig);
  emitLog(logger, 'debug', 'cli.nx_command', {
    command,
    services,
    nxCommand: ['pnpm', ...nxArgs].join(' '),
    servicePorts
  });

  if (flags.dryRun) {
    emitLog(logger, 'info', 'cli.dry_run_summary', {
      command,
      services,
      nxCommand: ['pnpm', ...nxArgs].join(' '),
      servicePorts
    });
    process.exit(0);
  }

  const env = buildEnv(runtimeConfig, runtimeConfigPath, servicePorts);
  const exitCode = await runCommand(nxArgs, env);
  if (exitCode === 0) {
    emitLog(logger, 'info', 'cli.flow_completed', { command, services, exitCode });
    process.exit(0);
  }

  emitLog(logger, 'error', 'cli.flow_failed', { command, services, exitCode });
  process.exit(exitCode);
}

main().catch((error: unknown) => {
  const logger = createCliLogger('debug');

  if (error instanceof Error) {
    emitLog(logger, 'error', 'cli.unhandled_error', {
      message: error.message,
      error,
      stack: error.stack,
      cause: error.cause
    });
  } else {
    emitLog(logger, 'error', 'cli.unhandled_error', {
      message: String(error),
      thrown: error
    });
  }

  process.exit(1);
});
