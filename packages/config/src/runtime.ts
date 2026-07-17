import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { isAbsolute, resolve } from 'node:path';

import { parseConfigIni } from './parser.js';

import type { ConfigSchemaType } from './schemas.js';

export const DEFAULT_CONFIG_FILE = 'config.ini';

export interface LoadConfigInput {
  configFilePath?: string;
  cwd?: string;
}

export function expandPath(pathValue: string, cwd = process.cwd()): string {
  const normalizedPath = pathValue.replace(/["'`]+/g, '').trim();

  if (normalizedPath === '~') {
    return homedir();
  }

  if (normalizedPath.startsWith('~/')) {
    return resolve(homedir(), normalizedPath.slice(2));
  }

  return isAbsolute(normalizedPath) ? resolve(normalizedPath) : resolve(cwd, normalizedPath);
}

/** Reads the service-local `--itw-config <path>` launch argument without using environment variables. */
export function getConfigFilePathFromArgv(argv: readonly string[] = process.argv): string | undefined {
  for (const [index, argument] of argv.entries()) {
    if (argument === '--itw-config') return argv[index + 1];
    if (argument.startsWith('--itw-config=')) return argument.slice('--itw-config='.length);
  }

  return undefined;
}

export function resolveConfigFilePath(input: LoadConfigInput = {}): string {
  return expandPath(
    input.configFilePath ?? getConfigFilePathFromArgv() ?? DEFAULT_CONFIG_FILE,
    input.cwd ?? process.cwd()
  );
}

export function expandConfigDataDir(config: ConfigSchemaType, cwd = process.cwd()): ConfigSchemaType {
  return {
    ...config,
    global: {
      ...config.global,
      data_dir: expandPath(config.global.data_dir, cwd)
    }
  };
}

export function loadConfig(input: LoadConfigInput = {}): ConfigSchemaType {
  const cwd = input.cwd ?? process.cwd();
  const configFilePath = resolveConfigFilePath({ configFilePath: input.configFilePath, cwd });

  if (!existsSync(configFilePath)) {
    throw new Error(`Config file not found at path: ${configFilePath}`);
  }

  return expandConfigDataDir(parseConfigIni(configFilePath), cwd);
}
