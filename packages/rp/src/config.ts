import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { resolve } from 'node:path';

import { z } from 'zod';

export const DEFAULT_HOST = '0.0.0.0';
export const DEFAULT_PORT = 8080;
export const DEFAULT_DATA_DIR = resolve(homedir(), '.itw-conformance-tool');

export const rpConfigSchema = z.object({
  host: z.string().min(1),
  port: z.number().int().min(1).max(65535),
  baseUrl: z.string().url(),
  dataDir: z.string().min(1),
  configFilePath: z.string().min(1)
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

type IniConfig = Record<string, Record<string, string>>;

function stripComment(input: string): string {
  const semicolonIndex = input.indexOf(';');
  const hashIndex = input.indexOf('#');
  if (semicolonIndex === -1 && hashIndex === -1) {
    return input.trim();
  }
  if (semicolonIndex === -1) {
    return input.slice(0, hashIndex).trim();
  }
  if (hashIndex === -1) {
    return input.slice(0, semicolonIndex).trim();
  }
  return input.slice(0, Math.min(semicolonIndex, hashIndex)).trim();
}

export function parseIni(iniRaw: string): IniConfig {
  const config = Object.create(null) as IniConfig;
  let currentSection = '';

  for (const rawLine of iniRaw.split(/\r?\n/u)) {
    const line = stripComment(rawLine);
    if (line.length === 0) {
      continue;
    }

    if (line.startsWith('[') && line.endsWith(']')) {
      currentSection = line.slice(1, -1).trim().toLowerCase();
      if (currentSection.length > 0 && config[currentSection] === undefined) {
        config[currentSection] = Object.create(null);
      }
      continue;
    }

    const separatorIndex = line.indexOf('=');
    if (separatorIndex === -1 || currentSection.length === 0) {
      continue;
    }

    const key = line.slice(0, separatorIndex).trim().toLowerCase();
    const value = line.slice(separatorIndex + 1).trim();
    if (key.length === 0 || key === '__proto__' || key === 'constructor' || key === 'prototype') {
      continue;
    }

    config[currentSection] ??= Object.create(null);
    config[currentSection][key] = value;
  }

  return config;
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

function parsePortFromString(value: string | undefined, source: string, fallback: number): number {
  if (value === undefined || value.length === 0) {
    return fallback;
  }
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`Invalid rp.port value in ${source}: ${value}`);
  }
  return port;
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

function loadIniFile(configFilePath: string): { ini?: IniConfig; found: boolean } {
  if (!existsSync(configFilePath)) {
    return { found: false };
  }
  const raw = readFileSync(configFilePath, { encoding: 'utf8' });
  return { ini: parseIni(raw), found: true };
}

export function deriveBaseUrl(input: { host: string; port: number }): string {
  // INI [rp].host can be 0.0.0.0 to listen on all interfaces, but the public
  // base URL should be addressable — fall back to localhost in that case.
  const reachableHost = input.host === '0.0.0.0' ? 'localhost' : input.host;
  return `http://${reachableHost}:${input.port}`;
}

export function loadRpConfig(input: LoadRpConfigInput): LoadRpConfigResult {
  const env = input.env ?? process.env;
  const { ini, found } = loadIniFile(input.configFilePath);

  const rpSection = ini?.rp;
  const globalSection = ini?.global;

  const port =
    parsePortOverride(env, 'ITW_CT_RP_PORT') ??
    parsePortFromString(rpSection?.port, input.configFilePath, DEFAULT_PORT);

  const dataDirOverride = env.ITW_CT_DATA_DIR;
  const dataDirFromIni = globalSection?.data_dir;
  const dataDir =
    dataDirOverride !== undefined && dataDirOverride.trim().length > 0
      ? expandHome(dataDirOverride.trim())
      : dataDirFromIni !== undefined && dataDirFromIni.trim().length > 0
        ? expandHome(dataDirFromIni.trim())
        : DEFAULT_DATA_DIR;

  const host = DEFAULT_HOST;

  const baseUrlOverride = env.ITW_CT_RP_BASE_URL?.trim();
  const baseUrlCandidate =
    baseUrlOverride && baseUrlOverride.length > 0 ? baseUrlOverride : deriveBaseUrl({ host, port });
  let baseUrl = baseUrlCandidate;
  while (baseUrl.endsWith('/')) {
    baseUrl = baseUrl.slice(0, -1);
  }
  const config = rpConfigSchema.parse({
    host,
    port,
    baseUrl,
    dataDir,
    configFilePath: input.configFilePath
  });

  return { config, configFileFound: found };
}
