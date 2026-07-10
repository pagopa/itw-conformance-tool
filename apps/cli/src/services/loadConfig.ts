import { resolve } from 'node:path';

import { DEFAULT_CONFIG, parseConfigIni, type ConfigSchemaType } from '@itw-conformance-tool/config';

import { expandPath } from '../utils/path.js';
import { existsFileSync } from '../utils/search.js';

import type { CliFlags } from '../types/types.js';

export type LoadConfigResult = { data: ConfigSchemaType; configFileFound: boolean };

const DEFAULT_CONFIG_FILE = 'config.ini';
const MISSING_CONFIG_WARNING = `
Warning: No configuration file found. Using default configuration values.
You can create a configuration file named '${DEFAULT_CONFIG_FILE}' in the current directory to customize the settings.
`;

type ConfigLookupResult = { configFileFound: boolean; configFilePath?: string };

function getConfigFile(flags: CliFlags): ConfigLookupResult {
  if (flags.config.value) {
    const configFilePath = expandPath(flags.config.path);

    if (!existsFileSync(configFilePath)) {
      throw new Error(`Config file not found at path: ${configFilePath}`);
    }

    return { configFileFound: true, configFilePath };
  }

  const defaultConfigPath = resolve(process.cwd(), DEFAULT_CONFIG_FILE);

  if (existsFileSync(defaultConfigPath)) {
    return { configFileFound: true, configFilePath: defaultConfigPath };
  }

  return { configFileFound: false };
}

function readConfig(configFilePath: string | undefined): ConfigSchemaType {
  return configFilePath ? parseConfigIni(configFilePath) : DEFAULT_CONFIG;
}

function expandConfigDataDir(data: ConfigSchemaType): ConfigSchemaType {
  return {
    ...data,
    global: {
      ...data.global,
      data_dir: expandPath(data.global.data_dir)
    }
  };
}

/** It loads the configuration file based on the provided CLI flags and root path.
 *
 * @param flags - The command-line flags that may contain the path to the configuration file.
 * @returns The loaded configuration object.
 */
export function loadConfig(flags: CliFlags): LoadConfigResult {
  const { configFileFound, configFilePath } = getConfigFile(flags);

  if (!configFileFound) {
    process.stdout.write(MISSING_CONFIG_WARNING);
  }

  return { data: expandConfigDataDir(readConfig(configFilePath)), configFileFound };
}
