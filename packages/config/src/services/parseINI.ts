import { existsSync, readFileSync } from 'node:fs';

import { parse } from 'ini';

import { ConfigSchema, DEFAULT_CONFIG } from '../schemas/schemas.js';

import type { ParseINIReturn } from '../types/types.js';

/** Read config file and parse it into a valid one.
 *
 * @param iniPath - The path to the config file.
 * @returns A valid config object.
 */
export function parseINI(iniPath: string): ParseINIReturn {
  if (!existsSync(iniPath)) {
    return {
      ok: false,
      error: `Config file not found at path: ${iniPath}`,
      data: DEFAULT_CONFIG
    };
  }

  try {
    const rawConfigContent = readFileSync(iniPath, 'utf-8');
    const parsedConfig = parse(rawConfigContent);

    const result = ConfigSchema.safeParse(parsedConfig);

    if (!result.success) {
      throw new Error(result.error.message);
    }

    return {
      ok: true,
      data: result.data
    };
  } catch (error: unknown) {
    return {
      ok: false,
      error: `Invalid config file: ${error instanceof Error ? error.message : JSON.stringify(error)}`,
      data: DEFAULT_CONFIG
    };
  }
}
