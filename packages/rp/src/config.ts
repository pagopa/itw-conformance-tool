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
  let baseUrl = baseUrlCandidate;
  while (baseUrl.endsWith('/')) {
    baseUrl = baseUrl.slice(0, -1);
  }

  const trustAnchorUrlOverride = env.ITW_CT_RP_TRUST_ANCHOR_URL?.trim();
  const trustAnchorUrl =
    trustAnchorUrlOverride && trustAnchorUrlOverride.length > 0 ? trustAnchorUrlOverride : data.rp.trust_anchor_url;

  const signingKeyPathOverride = env.ITW_CT_RP_SIGNING_KEY_PATH?.trim();
  const signingKeyPath =
    signingKeyPathOverride && signingKeyPathOverride.length > 0 ? signingKeyPathOverride : data.rp.signing_key_path;

  const x5cCertPathOverride = env.ITW_CT_RP_X5C_CERT_PATH?.trim();
  const x5cCertPath =
    x5cCertPathOverride && x5cCertPathOverride.length > 0 ? x5cCertPathOverride : data.rp.x5c_cert_path;

  const config = rpConfigSchema.parse({
    host,
    port,
    baseUrl,
    dataDir,
    configFilePath: input.configFilePath,
    trustAnchorUrl,
    signingKeyPath,
    x5cCertPath
  });

  return { config, configFileFound };
}
