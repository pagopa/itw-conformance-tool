import { spawn } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createInterface } from 'node:readline';

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
  logLevel: LogLevel;
  target: NxTarget;
  tls: TlsConfig;
  nx: NxConfig;
}

interface RawConfig {
  endpoint?: unknown;
  credentialTypes?: unknown;
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
  process.stdout.write('  --unsafe-tls                        Disable TLS certificate verification\n');
  process.stdout.write('  --tls-ca-file <path>                CA file path for TLS verification\n');
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

const logLevelPriority: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40
};

function shouldWriteLog(eventLevel: LogLevel, threshold: LogLevel): boolean {
  return logLevelPriority[eventLevel] >= logLevelPriority[threshold];
}

function writeLog(level: LogLevel, event: string, details: Record<string, unknown>, threshold: LogLevel = 'debug'): void {
  if (!shouldWriteLog(level, threshold)) {
    return;
  }

  const payload = {
    timestamp: new Date().toISOString(),
    level,
    event,
    ...details
  };

  const text = JSON.stringify(payload);

  process.stdout.write(`${text}\n`);
}

function parseBooleanFlag(current: boolean | undefined): boolean {
  return current ?? true;
}

function splitCsv(input: string): string[] {
  return input
    .split(',')
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

function parseArgs(argv: string[]): { command?: string; flags: CliFlags } {
  const flags: CliFlags = {
    dryRun: false,
    help: false
  };

  const [command, ...rest] = argv;

  for (let index = 0; index < rest.length; index += 1) {
    const arg = rest[index];

    if (arg === undefined) {
      continue;
    }

    switch (arg) {
      case '-h':
      case '--help':
        flags.help = true;
        break;
      case '--dry-run':
        flags.dryRun = true;
        break;
      case '--unsafe-tls':
        flags.unsafeTls = parseBooleanFlag(flags.unsafeTls);
        break;
      case '--skip-nx-cache':
        flags.skipNxCache = parseBooleanFlag(flags.skipNxCache);
        break;
      case '-c':
      case '--config': {
        const value = rest[index + 1];
        if (value === undefined) {
          throw new Error(`${arg} requires a value`);
        }
        flags.configFile = value;
        index += 1;
        break;
      }
      case '-e':
      case '--endpoint': {
        const value = rest[index + 1];
        if (value === undefined) {
          throw new Error(`${arg} requires a value`);
        }
        flags.endpoint = value;
        index += 1;
        break;
      }
      case '--credential-types': {
        const value = rest[index + 1];
        if (value === undefined) {
          throw new Error(`${arg} requires a value`);
        }
        flags.credentialTypes = splitCsv(value);
        index += 1;
        break;
      }
      case '--log-level': {
        const value = rest[index + 1];
        if (value === undefined) {
          throw new Error(`${arg} requires a value`);
        }
        if (!isLogLevel(value)) {
          throw new Error(`Invalid log level: ${value}`);
        }
        flags.logLevel = value;
        index += 1;
        break;
      }
      case '--target': {
        const value = rest[index + 1];
        if (value === undefined) {
          throw new Error(`${arg} requires a value`);
        }
        if (!isNxTarget(value)) {
          throw new Error(`Invalid target: ${value}`);
        }
        flags.target = value;
        index += 1;
        break;
      }
      case '--tls-ca-file': {
        const value = rest[index + 1];
        if (value === undefined) {
          throw new Error(`${arg} requires a value`);
        }
        flags.tlsCaFile = value;
        index += 1;
        break;
      }
      default:
        throw new Error(`Unknown option: ${arg}`);
    }
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
  const raw = readFileSync(resolvedPath, { encoding: 'utf8' });
  const parsed = JSON.parse(raw) as unknown;

  if (parsed === null || typeof parsed !== 'object') {
    throw new Error(`Invalid config file format: ${resolvedPath}`);
  }

  return parsed as RawConfig;
}

function normalizeRawConfig(raw: RawConfig): Partial<RuntimeConfig> {
  const result: Partial<RuntimeConfig> = {};

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
    result.tls = normalizedTls as TlsConfig;
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
    result.nx = normalizedNx as NxConfig;
  }

  return result;
}

function mergeConfig(flow: Flow, fileConfig: Partial<RuntimeConfig>, flags: CliFlags): RuntimeConfig {
  const defaults = defaultConfigs[flow];

  const merged: RuntimeConfig = {
    endpoint: flags.endpoint ?? fileConfig.endpoint ?? defaults.endpoint,
    credentialTypes: flags.credentialTypes ?? fileConfig.credentialTypes ?? defaults.credentialTypes,
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
    console.warn(
      '[warn] Unsafe TLS mode enabled: disabling TLS certificate verification for the delegated process by setting NODE_TLS_REJECT_UNAUTHORIZED=0.'
    );
    env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  }

  return env;
}

function pipeChildOutput(
  stream: NodeJS.ReadableStream,
  level: LogLevel,
  flow: Flow,
  project: string,
  target: NxTarget,
  source: 'stdout' | 'stderr'
): Promise<void> {
  return new Promise((resolve, reject) => {
    const interfaceHandle = createInterface({ input: stream, crlfDelay: Infinity });

    interfaceHandle.on('line', (line) => {
      if (line.trim().length === 0) {
        return;
      }

      writeLog(level, 'cli.nx_output', {
        flow,
        project,
        source,
        target,
        line
      });
    });

    interfaceHandle.once('error', reject);
    interfaceHandle.once('close', () => {
      resolve();
    });
  });
}

async function runCommand(flow: Flow, runtimeConfig: RuntimeConfig, args: string[], env: NodeJS.ProcessEnv): Promise<number> {
  const child = spawn('pnpm', args, {
    stdio: 'pipe',
    env
  });

  if (child.stdout === null || child.stderr === null) {
    throw new Error('Failed to capture Nx output streams');
  }

  const project = flowToProject[flow];

  const exitCodePromise = new Promise<number>((resolveExitCode, reject) => {
    child.once('error', reject);
    child.once('close', (code) => {
      resolveExitCode(code ?? 1);
    });
  });

  const outputPromise = Promise.all([
    pipeChildOutput(child.stdout, 'info', flow, project, runtimeConfig.target, 'stdout'),
    pipeChildOutput(child.stderr, 'error', flow, project, runtimeConfig.target, 'stderr')
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

  const env = buildEnv(command, runtimeConfig, flags.configFile);
  const nxArgs = buildNxArgs(command, runtimeConfig);

  writeLog('debug', 'cli.runtime_config_resolved', {
    flow: command,
    target: runtimeConfig.target,
    endpoint: runtimeConfig.endpoint,
    credentialTypes: runtimeConfig.credentialTypes,
    tls: runtimeConfig.tls,
    skipNxCache: runtimeConfig.nx.skipCache,
    configFile: flags.configFile
  }, runtimeConfig.logLevel);

  writeLog('debug', 'cli.nx_command', {
    command: ['pnpm', ...nxArgs].join(' ')
  }, runtimeConfig.logLevel);

  if (flags.dryRun) {
    process.exit(0);
  }

  const exitCode = await runCommand(command, runtimeConfig, nxArgs, env);

  if (exitCode === 0) {
    writeLog('info', 'cli.flow_completed', {
      flow: command,
      exitCode
    }, runtimeConfig.logLevel);
    process.exit(0);
  }

  writeLog('error', 'cli.flow_failed', {
    flow: command,
    exitCode
  }, runtimeConfig.logLevel);
  process.exit(exitCode);
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  writeLog('error', 'cli.unhandled_error', {
    message
  });
  process.exit(1);
});
