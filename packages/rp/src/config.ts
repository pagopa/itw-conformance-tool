import { homedir } from 'node:os';
import { join, resolve } from 'node:path';

import { loadConfig, resolveConfigFilePath } from '@itw-conformance-tool/config';
import { z } from 'zod';

export const DEFAULT_DATA_DIR = resolve(homedir(), '.itw-conformance-tool');

export const rpConfigSchema = z.object({
  url: z.url(),
  entityId: z.url(),
  dataDir: z.string().min(1),
  configFilePath: z.string().min(1),
  trustAnchorUrl: z.string().min(1).optional(),
  x5cCertPath: z.string().min(1)
});

export type RpConfig = z.infer<typeof rpConfigSchema>;

export interface LoadRpConfigInput {
  configFilePath?: string;
}

export interface LoadRpConfigResult {
  config: RpConfig;
}

export interface RpTlsPaths {
  certPath: string;
  keyPath: string;
}

function trimTrailingSlashes(value: string): string {
  let result = value;
  while (result.endsWith('/')) {
    result = result.slice(0, -1);
  }
  return result;
}

export function loadRpConfig(input: LoadRpConfigInput = {}): LoadRpConfigResult {
  const configFilePath = resolveConfigFilePath({ configFilePath: input.configFilePath });
  const data = loadConfig({ configFilePath });
  const url = data['relying-party'].url;
  const dataDir = data.global.data_dir;
  const baseUrl = trimTrailingSlashes(url);
  const entityIdFromConfig = data['relying-party'].entity_id.trim();
  const entityId = trimTrailingSlashes(entityIdFromConfig.length > 0 ? entityIdFromConfig : baseUrl);
  const trustAnchorUrlCandidate = data['relying-party'].trust_anchor_url?.trim();
  const trustAnchorUrl =
    trustAnchorUrlCandidate && trustAnchorUrlCandidate.length > 0 ? trustAnchorUrlCandidate : undefined;

  const config = rpConfigSchema.parse({
    url,
    entityId,
    dataDir,
    configFilePath,
    trustAnchorUrl,
    x5cCertPath: join(dataDir, 'rp/x5c-cert.pem')
  });

  return { config };
}
