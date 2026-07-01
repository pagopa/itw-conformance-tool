import { resolve } from 'node:path';

import { parseINI, type ParseINIReturn } from '@itw-conformance-tool/config';

import { expandPath } from '../utils/path.js';
import { existsFileSync } from '../utils/search.js';

import type { CLIFlags } from '../types/types.js';

export type LoadConfigsReturn = ParseINIReturn & { configFileFound: boolean };

/** It loads the configuration file based on the provided CLI flags and root path.
 *
 * @param flags - The command-line flags that may contain the path to the configuration file.
 * @returns The loaded configuration object.
 */
export function loadConfigs(flags: CLIFlags): LoadConfigsReturn {
  let parsedConfig = parseINI('.');
  let configFileExists = false;

  if (flags.config.value) {
    const configFilePath = expandPath(flags.config.path);
    const alreadyExists = existsFileSync(configFilePath);

    if (alreadyExists) {
      parsedConfig = parseINI(configFilePath);
      configFileExists = true;
    }
  } else {
    const defaultConfigPath = resolve(process.cwd(), 'config.ini');
    if (existsFileSync(defaultConfigPath)) {
      parsedConfig = parseINI(defaultConfigPath);
      configFileExists = true;
    }
  }

  if (!configFileExists) {
    process.stdout.write(
      `WARN: config.ini not found. Starting with default values.` +
        `\n      Run \`itw-conformance-tool init\` to create the configuration file.\n`
    );
  }

  parsedConfig.data.global.data_dir = expandPath(parsedConfig.data.global.data_dir);
  return { ...parsedConfig, configFileFound: configFileExists };
}
