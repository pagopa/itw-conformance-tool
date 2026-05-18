import { z } from 'zod';

export const DEFAULT_HOST = 'localhost';
export const DEFAULT_PORT = 8080;
export const DEFAULT_DATA_DIR = './data';

const rpConfigSchema = z.object({
  host: z.string().default(DEFAULT_HOST),
  port: z.number().int().positive().default(DEFAULT_PORT),
  dataDir: z.string().default(DEFAULT_DATA_DIR),
  baseUrl: z.string().url().optional()
});

export type RpConfig = z.infer<typeof rpConfigSchema>;

export interface LoadRpConfigInput {
  configFile?: string;
  env?: NodeJS.ProcessEnv;
}

export interface LoadRpConfigResult {
  config: RpConfig;
  baseUrl: string;
}

/**
 * Load RP configuration from ini file or environment variables
 */
export async function loadRpConfig({ env = process.env }: LoadRpConfigInput = {}): Promise<LoadRpConfigResult> {
  const host = env.ITW_CT_RP_HOST || DEFAULT_HOST;
  const port = env.ITW_CT_RP_PORT ? parseInt(env.ITW_CT_RP_PORT, 10) : DEFAULT_PORT;
  const dataDir = env.ITW_CT_DATA_DIR || DEFAULT_DATA_DIR;
  const baseUrl = env.ITW_CT_RP_BASE_URL || `http://${host}:${port}`;

  const config = rpConfigSchema.parse({
    host,
    port,
    dataDir,
    baseUrl
  });

  return { config, baseUrl };
}

export function parseIni(content: string): Record<string, Record<string, string>> {
  const result: Record<string, Record<string, string>> = {};
  let section = '';

  for (const line of content.split('\n')) {
    const trimmed = line.trim();

    if (!trimmed || trimmed.startsWith(';')) continue;

    if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
      section = trimmed.slice(1, -1);
      result[section] = {};
    } else if (section) {
      const [key, ...values] = trimmed.split('=');
      if (key) {
        result[section][key.trim()] = values.join('=').trim();
      }
    }
  }

  return result;
}

export function deriveBaseUrl(host: string, port: number): string {
  return `http://${host}:${port}`;
}

export const rpConfigSchema_export = rpConfigSchema;
