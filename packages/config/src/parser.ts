import { readFileSync } from 'node:fs';

import { parse } from 'ini';

import { ConfigSchema, type ConfigSchemaType } from './schemas.js';

/**
 * Reads an INI config file and returns the Zod-validated config object.
 */
export function parseConfigIni(iniPath: string): ConfigSchemaType {
  return ConfigSchema.parse(parse(readFileSync(iniPath, 'utf8')));
}
