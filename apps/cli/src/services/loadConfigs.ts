import { join } from 'node:path';

import { parseINI, type ConfigType } from '@itw-conformance-tool/config';

import { getDefaultConfigs } from '../templates/templates.js';
import { existsFileSync, expandPath } from '../utils/search.js';

import type { CLIFlags } from '../types/types.js';
import type { Level } from '@itw-conformance-tool/logger';

/** It loads the configuration file based on the provided CLI flags and root path.
 *
 * @param flags - The command-line flags that may contain the path to the configuration file.
 * @param rootPath - The root directory of the project.
 * @param emitLog - A function used to emit structured log messages.
 * @returns An object containing the loaded configuration and a boolean indicating whether the configuration file exists.
 */
export function loadConfigs(
  flags: CLIFlags,
  rootPath: string,
  emitLog: (event: string, type?: Level) => void
): { configs: ConfigType; configFileExists: boolean } {
  let configs = getDefaultConfigs(rootPath);
  let configFileExists = false;

  if (flags.config.value) {
    configFileExists = existsFileSync(flags.config.path);
    if (configFileExists) {
      const parsedINI = parseINI(flags.config.path);
      configs = parsedINI.data;
      emitLog(`Config file found at: ${flags.config.path}\n` + `Content:\n${JSON.stringify(configs, null, 2)}`);
      configs.global.data_dir = expandPath(configs.global.data_dir, rootPath);
    } else {
      emitLog(
        `Config file not found at specified path: ${flags.config.path}. Starting with default values.\n` +
          `Content:\n${JSON.stringify(configs, null, 2)}`
      );
    }
    return { configs, configFileExists };
  }

  const defaultConfigPath = join(rootPath, 'config.ini');
  configFileExists = existsFileSync(defaultConfigPath);
  if (configFileExists) {
    const parsedINI = parseINI(defaultConfigPath);
    configs = parsedINI.data;
    emitLog(`Config file found at: ${defaultConfigPath}` + '\n' + `Content:\n${JSON.stringify(configs, null, 2)}`);
    configs.global.data_dir = expandPath(configs.global.data_dir, rootPath);
  } else {
    emitLog(
      `Config file not found at default path: ${defaultConfigPath}.\nStarting with default values.\n` +
        `Content:\n${JSON.stringify(configs, null, 2)}`
    );
  }

  return { configs, configFileExists };
}
