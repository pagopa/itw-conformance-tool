import { resolve } from 'node:path';

import { DEFAULT_CONFIG, parseConfigIni, type ConfigSchemaType } from '@itw-conformance-tool/config';

import { expandPath } from '../utils/path.js';
import { existsFileSync } from '../utils/search.js';

import type { CLIFlags } from '../types/types.js';

export type LoadConfigResult = { data: ConfigSchemaType; configFileFound: boolean };

/** It loads the configuration file based on the provided CLI flags and root path.
 *
 * @param flags - The command-line flags that may contain the path to the configuration file.
 * @returns The loaded configuration object.
 */
export function loadConfig(flags: CLIFlags): LoadConfigResult {
  let configFileFound = false;
  let data: ConfigSchemaType = DEFAULT_CONFIG;

  if (flags.config.value) {
    const configFilePath = expandPath(flags.config.path);
    if (!existsFileSync(configFilePath)) {
      throw new Error(`Config file not found at path: ${configFilePath}`);
    }

    data = parseConfigIni(configFilePath);
    configFileFound = true;
  } else {
    const defaultConfigPath = resolve(process.cwd(), 'config.ini');
    if (existsFileSync(defaultConfigPath)) {
      data = parseConfigIni(defaultConfigPath);
      configFileFound = true;
    }
  }

  if (!configFileFound) {
    process.stdout.write(
      `WARN: config.ini not found. Starting with default values.` +
        `\n      Run \`itw-conformance-tool init\` to create the configuration file.\n`
    );
  }

  data.global.data_dir = expandPath(data.global.data_dir);
  return { data, configFileFound };
}
