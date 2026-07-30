import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { isAbsolute, resolve } from 'node:path';

import { parseConfigIni } from './parser.js';

import type { ConfigSchemaType } from './schemas.js';

export const DEFAULT_CONFIG_FILE = 'config.ini';

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

export function expandConfigDataDir(config: ConfigSchemaType, cwd = process.cwd()): ConfigSchemaType {
  return {
    ...config,
    global: {
      ...config.global,
      data_dir: expandPath(config.global.data_dir, cwd)
    }
  };
}

export function loadConfig(): ConfigSchemaType {
  const cwd = process.cwd();
  const configFilePath = expandPath(DEFAULT_CONFIG_FILE);

  if (!existsSync(configFilePath)) {
    throw new Error(`Config file not found at path: ${configFilePath}`);
  }

  return expandConfigDataDir(parseConfigIni(configFilePath), cwd);
}
