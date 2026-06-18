import { resolve } from 'node:path';

import { parseINI, type ConfigType } from '@itw-conformance-tool/config';

import { expandPath } from '../utils/path.js';
import { existsFileSync } from '../utils/search.js';

import type { CLIFlags } from '../types/types.js';

/** It loads the configuration file based on the provided CLI flags and root path.
 *
 * @param flags - The command-line flags that may contain the path to the configuration file.
 * @returns The loaded configuration object.
 */
export function loadConfigs(flags: CLIFlags): ConfigType {
  let configs = parseINI('.').data;
  let configFileExists = false;

  if (flags.config.value) {
    const configFilePath = expandPath(flags.config.path);
    const alreadyExists = existsFileSync(configFilePath);

    if (alreadyExists) {
      configs = parseINI(configFilePath).data;
      configFileExists = true;
    }
  } else {
    const defaultConfigPath = resolve(process.cwd(), 'config.ini');
    if (existsFileSync(defaultConfigPath)) {
      configs = parseINI(defaultConfigPath).data;
      configFileExists = true;
    }
  }

  if (!configFileExists) {
    process.stdout.write(
      `WARN: config.ini not found. Starting with default values.` +
        `\n      Run \`itw-conformance-tool init\` to create the configuration file.\n`
    );
  }

  configs.global.data_dir = expandPath(configs.global.data_dir);
  return configs;
}
