import { readFile } from 'node:fs/promises';

import { parse } from 'ini';
import { z } from 'zod';

const ConfigSchema = z.object({
  global: z.object({
    data_dir: z.string().min(1).default('~/.itw-conformance-tool'),
    log_level: z.enum(['debug', 'info', 'warn', 'error']).default('info')
  }).default({
    data_dir: '~/.itw-conformance-tool', 
    log_level: 'info'
  }),
  'itw-credential-issuer': z.object({
    port: z.coerce.number().default(3000),
    credential_types: z
      .string()
      .refine(
        (s) => s.split(',').every((v) => ['pid', 'mdl', 'badge', 'eaa'].includes(v.trim())),
      )
      .default('pid,mdl,badge,eaa')
  }).default({
    port: 3000, 
    credential_types: 'pid,mdl,badge,eaa'
  }),
  rp: z.object({
    port: z.coerce.number().default(8080),
  }).default({
    port: 8080
  }),
})

export type Config = z.infer<typeof ConfigSchema>;

/**
 * Read config file and parse it into a valid one.
 * @param path - The path to the config file.
 * @returns A valid config object.
 */
export async function readConfig(path: string): Promise<Config> {
  let parsedConfig = {};

  try {
    const rawConfigContent = await readFile(path, 'utf-8');
    parsedConfig = parse(rawConfigContent);
  } catch (error: unknown) {
    // TODO: log the error
  }

  return ConfigSchema.parse(parsedConfig);
}
