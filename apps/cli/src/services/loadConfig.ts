import {
  expandPath,
  loadConfig as loadToolConfig,
  resolveConfigFilePath,
  type ConfigSchemaType
} from '@itw-conformance-tool/config';

import { existsFileSync } from '../utils/search.js';

import type { CliFlags } from '../types/types.js';

export interface LoadConfigResult {
  data: ConfigSchemaType;
  configFilePath: string;
}

/** It loads the configuration file based on the provided CLI flags and root path.
 *
 * @param flags - The command-line flags that may contain the path to the configuration file.
 * @returns The loaded configuration object.
 */
export function loadConfig(flags: CliFlags): LoadConfigResult {
  const configFilePath = flags.config.value ? expandPath(flags.config.path) : undefined;

  if (configFilePath !== undefined && !existsFileSync(configFilePath)) {
    throw new Error(`Config file not found at path: ${configFilePath}`);
  }

  const data = loadToolConfig({ configFilePath });

  return { data, configFilePath: configFilePath ?? resolveConfigFilePath() };
}
