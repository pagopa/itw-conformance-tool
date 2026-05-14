import { spawn } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { parseArgs as parseNodeArgs } from 'node:util';

import { loggerOptions as sharedLoggerOptions } from '@itw-conformance-tool/logger';
import pino, { type Logger as PinoLogger, type LoggerOptions } from 'pino';

type LogLevel = 'debug' | 'info' | 'warn' | 'error';
type Flow = 'issuance' | 'presentation';
type NxTarget = 'test' | 'serve';

interface TlsConfig {
  unsafe: boolean;
  caFile?: string;
}

interface NxConfig {
  skipCache: boolean;
  extraArgs: string[];
}

interface RuntimeConfig {
  endpoint: string;
  credentialTypes: string[];
  init: boolean;
  logLevel: LogLevel;
  target: NxTarget;
  tls: TlsConfig;
  nx: NxConfig;
}

interface NormalizedRuntimeConfig {
  endpoint?: RuntimeConfig['endpoint'];
  credentialTypes?: RuntimeConfig['credentialTypes'];
  init?: RuntimeConfig['init'];
  logLevel?: RuntimeConfig['logLevel'];
  target?: RuntimeConfig['target'];
  tls?: Partial<TlsConfig>;
  nx?: Partial<NxConfig>;
}

interface RawConfig {
  endpoint?: unknown;
  credentialTypes?: unknown;
  init?: unknown;
  logLevel?: unknown;
  target?: unknown;
  tls?: {
    unsafe?: unknown;
    caFile?: unknown;
  };
  nx?: {
    skipCache?: unknown;
    extraArgs?: unknown;
  };
}

interface CliFlags {
  configFile?: string;
  endpoint?: string;
  credentialTypes?: string[];
  init?: boolean;
  logLevel?: LogLevel;
  target?: NxTarget;
  unsafeTls?: boolean;
  tlsCaFile?: string;
  skipNxCache?: boolean;
  dryRun: boolean;
  help: boolean;
}

const cliName = 'pnpm conformance';

const defaultConfigs: Record<Flow, RuntimeConfig> = {
  issuance: {
    endpoint: 'http://localhost:3000',
    credentialTypes: ['PID'],
    init: false,
    logLevel: 'info',
    target: 'test',
    tls: {
      unsafe: false
    },
    nx: {
      skipCache: false,
      extraArgs: []
    }
  },
  presentation: {
    endpoint: 'http://localhost:3000',
    credentialTypes: ['PID'],
    init: false,
    logLevel: 'info',
    target: 'test',
    tls: {
      unsafe: false
    },
    nx: {
      skipCache: false,
      extraArgs: []
    }
  }
};

const flowToProject: Record<Flow, string> = {
  issuance: 'itw-credential-issuer',
  presentation: 'itw-relying-party'
};

type CliLogger = PinoLogger;

function printHelp(): void {
  process.stdout.write(`\n${cliName} - Headless CLI for ITW Conformance flows\n\n`);
  process.stdout.write('Usage:\n');
  process.stdout.write(`  ${cliName} <command> [options]\n\n`);
  process.stdout.write('Commands:\n');
  process.stdout.write('  issuance       Run issuance flow against itw-credential-issuer Nx targets\n');
  process.stdout.write('  presentation   Run presentation flow against itw-relying-party Nx targets\n');
  process.stdout.write('  help           Show this help\n\n');
  process.stdout.write('Options:\n');
  process.stdout.write('  -c, --config <file>                 Runtime config file (JSON)\n');
  process.stdout.write('  -e, --endpoint <url>                Endpoint override\n');
  process.stdout.write('  --credential-types <list>           Comma-separated credential types\n');
  process.stdout.write('  --init                              Enable init mode\n');
  process.stdout.write('  --unsafe-tls                        Disable TLS certificate verification\n');
  process.stdout.write(
    '  --tls-ca-file <path>                Export CA file path as ITW_CT_TLS_CA_FILE for downstream consumers (not wired into Node TLS here)\n'
  );
  process.stdout.write('  --log-level <debug|info|warn|error> Log level for CLI logs\n');
  process.stdout.write('  --target <test|serve>               Nx target to execute (default: test)\n');
  process.stdout.write('  --skip-nx-cache                     Pass --skip-nx-cache to Nx\n');
  process.stdout.write('  --dry-run                           Print computed command and stop\n');
  process.stdout.write('  -h, --help                          Show help\n\n');
  process.stdout.write('Configuration priority:\n');
  process.stdout.write('  defaults -> custom config file -> CLI flags\n\n');
  process.stdout.write('Examples:\n');
  process.stdout.write(`  ${cliName} issuance --target test --endpoint https://issuer.example.com --log-level debug\n`);
  process.stdout.write(`  ${cliName} presentation -c ./conformance.runtime.json --credential-types PID,MDL\n\n`);
}

function createCliLogger(level: LogLevel): CliLogger {
  const loggerOptions: LoggerOptions = {
    ...sharedLoggerOptions,
    level,
    transport: undefined
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

function splitCsv(input: string): string[] {
  return input
    .split(',')
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
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
      config: {
        type: 'string',
        short: 'c'
      },
      endpoint: {
        type: 'string',
        short: 'e'
      },
      'credential-types': {
        type: 'string'
      },
      init: {
        type: 'boolean'
      },
      'log-level': {
        type: 'string'
      },
      target: {
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

  if (parsed.values.config !== undefined) {
    flags.configFile = parsed.values.config;
  }

  if (parsed.values.endpoint !== undefined) {
    flags.endpoint = parsed.values.endpoint;
  }

  if (parsed.values['credential-types'] !== undefined) {
    flags.credentialTypes = splitCsv(parsed.values['credential-types']);
  }

  if (parsed.values.init) {
    flags.init = true;
  }

  if (parsed.values['log-level'] !== undefined) {
    const logLevel = parsed.values['log-level'];
    if (!isLogLevel(logLevel)) {
      throw new Error(`Invalid log level: ${logLevel}`);
    }
    flags.logLevel = logLevel;
  }

  if (parsed.values.target !== undefined) {
    if (!isNxTarget(parsed.values.target)) {
      throw new Error(`Invalid target: ${parsed.values.target}`);
    }
    flags.target = parsed.values.target;
  }

  if (parsed.values['tls-ca-file'] !== undefined) {
    flags.tlsCaFile = parsed.values['tls-ca-file'];
  }

  return { command, flags };
}

function isLogLevel(value: string): value is LogLevel {
  return value === 'debug' || value === 'info' || value === 'warn' || value === 'error';
}

function isNxTarget(value: string): value is NxTarget {
  return value === 'test' || value === 'serve';
}

function isFlow(value: string): value is Flow {
  return value === 'issuance' || value === 'presentation';
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

function loadRawConfig(filePath?: string): RawConfig {
  if (filePath === undefined) {
    return {};
  }

  const resolvedPath = resolve(process.cwd(), filePath);
  let raw: string;

  try {
    raw = readFileSync(resolvedPath, { encoding: 'utf8' });
  } catch (error) {
    const { code } = error as NodeJS.ErrnoException;
    const codeSuffix = typeof code === 'string' ? ` (${code})` : '';
    throw new Error(`Failed to read config file passed via --config: ${resolvedPath}${codeSuffix}`, { cause: error });
  }

  let parsed: unknown;

  try {
    parsed = JSON.parse(raw) as unknown;
  } catch (error) {
    throw new Error(`Failed to parse config file JSON: ${resolvedPath}`, { cause: error });
  }

  if (parsed === null || typeof parsed !== 'object') {
    throw new Error(`Invalid config file format: ${resolvedPath}`);
  }

  return parsed as RawConfig;
}

function normalizeRawConfig(raw: RawConfig): NormalizedRuntimeConfig {
  const result: NormalizedRuntimeConfig = {};

  if (typeof raw.endpoint === 'string') {
    result.endpoint = raw.endpoint;
  }

  if (typeof raw.logLevel === 'string') {
    if (!isLogLevel(raw.logLevel)) {
      throw new Error(`Invalid config logLevel: ${String(raw.logLevel)}`);
    }
    result.logLevel = raw.logLevel;
  }

  if (typeof raw.target === 'string') {
    if (!isNxTarget(raw.target)) {
      throw new Error(`Invalid config target: ${String(raw.target)}`);
    }
    result.target = raw.target;
  }

  if (Array.isArray(raw.credentialTypes)) {
    result.credentialTypes = raw.credentialTypes
      .filter((value): value is string => typeof value === 'string')
      .map((value) => value.trim())
      .filter((value) => value.length > 0);
  }

  if (typeof raw.init === 'boolean') {
    result.init = raw.init;
  }

  const normalizedTls: Partial<TlsConfig> = {};
  if (raw.tls !== undefined && typeof raw.tls === 'object' && raw.tls !== null) {
    if (typeof raw.tls.unsafe === 'boolean') {
      normalizedTls.unsafe = raw.tls.unsafe;
    }
    if (typeof raw.tls.caFile === 'string') {
      normalizedTls.caFile = raw.tls.caFile;
    }
  }

  if (Object.keys(normalizedTls).length > 0) {
    result.tls = normalizedTls;
  }

  const normalizedNx: Partial<NxConfig> = {};
  if (raw.nx !== undefined && typeof raw.nx === 'object' && raw.nx !== null) {
    if (typeof raw.nx.skipCache === 'boolean') {
      normalizedNx.skipCache = raw.nx.skipCache;
    }
    if (Array.isArray(raw.nx.extraArgs)) {
      normalizedNx.extraArgs = raw.nx.extraArgs.filter((value): value is string => typeof value === 'string');
    }
  }

  if (Object.keys(normalizedNx).length > 0) {
    result.nx = normalizedNx;
  }

  return result;
}

function mergeConfig(flow: Flow, fileConfig: NormalizedRuntimeConfig, flags: CliFlags): RuntimeConfig {
  const defaults = defaultConfigs[flow];

  const merged: RuntimeConfig = {
    endpoint: flags.endpoint ?? fileConfig.endpoint ?? defaults.endpoint,
    credentialTypes: flags.credentialTypes ?? fileConfig.credentialTypes ?? defaults.credentialTypes,
    init: flags.init ?? fileConfig.init ?? defaults.init,
    logLevel: flags.logLevel ?? fileConfig.logLevel ?? defaults.logLevel,
    target: flags.target ?? fileConfig.target ?? defaults.target,
    tls: {
      unsafe: flags.unsafeTls ?? fileConfig.tls?.unsafe ?? defaults.tls.unsafe,
      caFile: flags.tlsCaFile ?? fileConfig.tls?.caFile ?? defaults.tls.caFile
    },
    nx: {
      skipCache: flags.skipNxCache ?? fileConfig.nx?.skipCache ?? defaults.nx.skipCache,
      extraArgs: fileConfig.nx?.extraArgs ?? defaults.nx.extraArgs
    }
  };

  if (merged.credentialTypes.length === 0) {
    throw new Error('credentialTypes cannot be empty');
  }

  return merged;
}

function buildNxArgs(flow: Flow, runtimeConfig: RuntimeConfig): string[] {
  const project = flowToProject[flow];
  const args = ['nx', 'run', `${project}:${runtimeConfig.target}`];

  if (runtimeConfig.nx.skipCache) {
    args.push('--skip-nx-cache');
  }

  // TODO(migration): map runtime options (endpoint, credential types, TLS settings) to real target inputs
  // once issuer/relying-party apps consume CLI-provided configuration directly (Nx args or app env contract).
  if (runtimeConfig.nx.extraArgs.length > 0) {
    args.push(...runtimeConfig.nx.extraArgs);
  }

  return args;
}

function buildEnv(flow: Flow, runtimeConfig: RuntimeConfig, configFile?: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    // TODO(migration): these ITW_CT_* variables are currently exported for downstream consumers only.
    // Wire delegated targets to read them (or replace with target-specific Nx args) during migration.
    ITW_CT_FLOW: flow,
    ITW_CT_ENDPOINT: runtimeConfig.endpoint,
    ITW_CT_CREDENTIAL_TYPES: runtimeConfig.credentialTypes.join(','),
    ITW_CT_INIT: runtimeConfig.init ? 'true' : 'false',
    ITW_CT_LOG_LEVEL: runtimeConfig.logLevel,
    ITW_CT_UNSAFE_TLS: runtimeConfig.tls.unsafe ? 'true' : 'false'
  };

  if (configFile !== undefined) {
    env.ITW_CT_CONFIG_FILE = resolve(process.cwd(), configFile);
  }

  if (runtimeConfig.tls.caFile !== undefined) {
    env.ITW_CT_TLS_CA_FILE = runtimeConfig.tls.caFile;
  }

  if (runtimeConfig.tls.unsafe) {
    env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  }

  return env;
}

function pipeChildOutput(stream: NodeJS.ReadableStream, logger: CliLogger, level: LogLevel): Promise<void> {
  return new Promise((resolve, reject) => {
    const interfaceHandle = createInterface({ input: stream, crlfDelay: Infinity });

    interfaceHandle.on('line', (line) => {
      if (line.trim().length === 0) {
        return;
      }

      emitLog(logger, level, 'cli.nx_output', { line });
    });

    interfaceHandle.once('error', reject);
    interfaceHandle.once('close', () => {
      resolve();
    });
  });
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

async function runCommand(
  flow: Flow,
  runtimeConfig: RuntimeConfig,
  args: string[],
  env: NodeJS.ProcessEnv,
  logger: CliLogger
): Promise<number> {
  const nxCliPath = resolveLocalNxCli();
  const nxArgs = args[0] === 'nx' ? args.slice(1) : args;
  const child = spawn(process.execPath, [nxCliPath, ...nxArgs], {
    stdio: 'pipe',
    env
  });

  if (child.stdout === null || child.stderr === null) {
    throw new Error('Failed to capture Nx output streams');
  }

  const project = flowToProject[flow];
  const commandLogger = logger.child({
    flow,
    project,
    target: runtimeConfig.target
  });

  const exitCodePromise = new Promise<number>((resolveExitCode, reject) => {
    child.once('error', reject);
    child.once('close', (code) => {
      resolveExitCode(code ?? 1);
    });
  });

  const outputPromise = Promise.all([
    pipeChildOutput(child.stdout, commandLogger.child({ source: 'stdout' }), 'info'),
    pipeChildOutput(child.stderr, commandLogger.child({ source: 'stderr' }), 'error')
  ]);

  const [exitCode] = await Promise.all([exitCodePromise, outputPromise]);
  return exitCode;
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

  if (!isFlow(command)) {
    throw new Error(`Unknown command: ${command}`);
  }

  resolveWorkspaceRoot(process.cwd());

  const rawConfig = loadRawConfig(flags.configFile);
  const fileConfig = normalizeRawConfig(rawConfig);
  const runtimeConfig = mergeConfig(command, fileConfig, flags);
  const logger = createCliLogger(runtimeConfig.logLevel);
  const commandLogger = logger.child({
    flow: command,
    project: flowToProject[command],
    target: runtimeConfig.target
  });

  const env = buildEnv(command, runtimeConfig, flags.configFile);
  const nxArgs = buildNxArgs(command, runtimeConfig);

  emitLog(commandLogger, 'debug', 'cli.runtime_config_resolved', {
    flow: command,
    target: runtimeConfig.target,
    endpoint: runtimeConfig.endpoint,
    credentialTypes: runtimeConfig.credentialTypes,
    init: runtimeConfig.init,
    tls: runtimeConfig.tls,
    skipNxCache: runtimeConfig.nx.skipCache,
    configFile: flags.configFile
  });

  emitLog(commandLogger, 'debug', 'cli.nx_command', {
    command: ['pnpm', ...nxArgs].join(' ')
  });

  if (runtimeConfig.tls.unsafe) {
    emitLog(commandLogger, 'warn', 'cli.unsafe_tls_enabled', {
      message: 'TLS certificate verification is disabled for the delegated process'
    });
  }

  if (flags.dryRun) {
    const dryRunLogger = createCliLogger('info').child({
      flow: command,
      project: flowToProject[command],
      target: runtimeConfig.target
    });
    emitLog(dryRunLogger, 'info', 'cli.dry_run_summary', {
      runtimeConfig,
      command: ['pnpm', ...nxArgs].join(' ')
    });
    process.exit(0);
  }

  const exitCode = await runCommand(command, runtimeConfig, nxArgs, env, logger);

  if (exitCode === 0) {
    emitLog(commandLogger, 'info', 'cli.flow_completed', {
      flow: command,
      exitCode
    });
    process.exit(0);
  }

  emitLog(commandLogger, 'error', 'cli.flow_failed', {
    flow: command,
    exitCode
  });
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
