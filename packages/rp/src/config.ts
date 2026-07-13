import { homedir } from 'node:os';
import { join, resolve } from 'node:path';

import { loadConfig, resolveConfigFilePath } from '@itw-conformance-tool/config';
import { z } from 'zod';

export const DEFAULT_HOST = '0.0.0.0';
export const DEFAULT_PORT = 8080;
export const DEFAULT_DATA_DIR = resolve(homedir(), '.itw-conformance-tool');

export const rpConfigSchema = z.object({
  host: z.string().min(1),
  port: z.number().int().min(1).max(65535),
  baseUrl: z.url(),
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

export function deriveBaseUrl(input: { host: string; port: number }): string {
  // INI [rp].host can be 0.0.0.0 to listen on all interfaces, but the public
  // base URL should be addressable — fall back to localhost in that case.
  const reachableHost = input.host === '0.0.0.0' ? 'localhost' : input.host;
  return `https://${reachableHost}:${input.port}`;
}

export function loadRpConfig(input: LoadRpConfigInput = {}): LoadRpConfigResult {
  const configFilePath = resolveConfigFilePath({ configFilePath: input.configFilePath });
  const data = loadConfig({ configFilePath });
  const port = data.rp.port;
  const dataDir = data.global.data_dir;
  const host = DEFAULT_HOST;
  const baseUrl = trimTrailingSlashes(deriveBaseUrl({ host, port }));
  const entityIdFromConfig = data.rp.entity_id.trim();
  const entityId = trimTrailingSlashes(entityIdFromConfig.length > 0 ? entityIdFromConfig : baseUrl);
  const trustAnchorUrlCandidate = data.rp.trust_anchor_url?.trim();
  const trustAnchorUrl =
    trustAnchorUrlCandidate && trustAnchorUrlCandidate.length > 0 ? trustAnchorUrlCandidate : undefined;

  const config = rpConfigSchema.parse({
    host,
    port,
    baseUrl,
    entityId,
    dataDir,
    configFilePath,
    trustAnchorUrl,
    x5cCertPath: join(dataDir, 'rp/x5c-cert.pem')
  });

  return { config };
}
