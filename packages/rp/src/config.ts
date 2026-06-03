import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { resolve } from 'node:path';

import { parseINI } from '@itw-conformance-tool/config';
import { z } from 'zod';

export const DEFAULT_HOST = '0.0.0.0';
export const DEFAULT_PORT = 8080;
export const DEFAULT_DATA_DIR = resolve(homedir(), '.itw-conformance-tool');

export const rpConfigSchema = z.object({
  host: z.string().min(1),
  port: z.number().int().min(1).max(65535),
  baseUrl: z.string().url(),
  entityId: z.string().url(),
  dataDir: z.string().min(1),
  configFilePath: z.string().min(1),
  trustAnchorUrl: z.string().url(),
  signingKeyPath: z.string().min(1),
  x5cCertPath: z.string().min(1)
});

export type RpConfig = z.infer<typeof rpConfigSchema>;

export interface LoadRpConfigInput {
  configFilePath: string;
  env?: NodeJS.ProcessEnv;
}

export interface LoadRpConfigResult {
  config: RpConfig;
  configFileFound: boolean;
}

function expandHome(pathValue: string): string {
  if (pathValue === '~') {
    return homedir();
  }
  if (pathValue.startsWith('~/')) {
    return resolve(homedir(), pathValue.slice(2));
  }
  return resolve(pathValue);
}

function parsePortOverride(env: NodeJS.ProcessEnv, variableName: string): number | undefined {
  const value = env[variableName];
  if (value === undefined || value.trim().length === 0) {
    return undefined;
  }
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`Invalid ${variableName} value: ${value}`);
  }
  return port;
}

export function deriveBaseUrl(input: { host: string; port: number }): string {
  // INI [rp].host can be 0.0.0.0 to listen on all interfaces, but the public
  // base URL should be addressable — fall back to localhost in that case.
  const reachableHost = input.host === '0.0.0.0' ? 'localhost' : input.host;
  return `http://${reachableHost}:${input.port}`;
}

export function loadRpConfig(input: LoadRpConfigInput): LoadRpConfigResult {
  const env = input.env ?? process.env;
  const configFileFound = existsSync(input.configFilePath);
  const { data } = parseINI(input.configFilePath);

  const port = parsePortOverride(env, 'ITW_CT_RP_PORT') ?? data.rp.port;

  const dataDirOverride = env.ITW_CT_DATA_DIR;
  const dataDir =
    dataDirOverride !== undefined && dataDirOverride.trim().length > 0
      ? expandHome(dataDirOverride.trim())
      : expandHome(data.global.data_dir);

  const host = DEFAULT_HOST;

  const baseUrlOverride = env.ITW_CT_RP_BASE_URL?.trim();
  const baseUrlCandidate =
    baseUrlOverride && baseUrlOverride.length > 0 ? baseUrlOverride : deriveBaseUrl({ host, port });

  const entityIdOverride = env.ITW_CT_RP_ENTITY_ID?.trim();
  const entityIdFromConfig = data.rp.entity_id?.trim();
  const entityIdCandidate =
    entityIdOverride && entityIdOverride.length > 0
      ? entityIdOverride
      : entityIdFromConfig && entityIdFromConfig.length > 0
        ? entityIdFromConfig
        : baseUrlCandidate;

  let baseUrl = baseUrlCandidate;
  while (baseUrl.endsWith('/')) {
    baseUrl = baseUrl.slice(0, -1);
  }

  let entityId = entityIdCandidate;
  while (entityId.endsWith('/')) {
    entityId = entityId.slice(0, -1);
  }
  const trustAnchorUrlOverride = env.ITW_CT_RP_TRUST_ANCHOR_URL?.trim();
  const trustAnchorUrlCandidate =
    trustAnchorUrlOverride && trustAnchorUrlOverride.length > 0 ? trustAnchorUrlOverride : data.rp.trust_anchor_url;
  const trustAnchorUrl = trustAnchorUrlCandidate.trim();

  const signingKeyPathOverride = env.ITW_CT_RP_SIGNING_KEY_PATH?.trim();
  const signingKeyPathCandidate =
    signingKeyPathOverride && signingKeyPathOverride.length > 0 ? signingKeyPathOverride : data.rp.signing_key_path;
  const signingKeyPathTrimmed = signingKeyPathCandidate.trim();
  const signingKeyPath = signingKeyPathTrimmed.length > 0 ? expandHome(signingKeyPathTrimmed) : signingKeyPathTrimmed;

  const x5cCertPathOverride = env.ITW_CT_RP_X5C_CERT_PATH?.trim();
  const x5cCertPathCandidate =
    x5cCertPathOverride && x5cCertPathOverride.length > 0 ? x5cCertPathOverride : data.rp.x5c_cert_path;
  const x5cCertPathTrimmed = x5cCertPathCandidate.trim();
  const x5cCertPath = x5cCertPathTrimmed.length > 0 ? expandHome(x5cCertPathTrimmed) : x5cCertPathTrimmed;

  const config = rpConfigSchema.parse({
    host,
    port,
    baseUrl,
    entityId,
    dataDir,
    configFilePath: input.configFilePath,
    trustAnchorUrl,
    signingKeyPath,
    x5cCertPath
  });

  return { config, configFileFound };
}
