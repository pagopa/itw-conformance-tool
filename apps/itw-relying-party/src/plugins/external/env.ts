import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { resolve } from 'node:path';

import fp from 'fastify-plugin';

interface RpRuntimeConfig {
  host: string;
  port: number;
  baseUrl: string;
  dataDir: string;
  configFilePath: string;
}

declare module 'fastify' {
  interface FastifyInstance {
    config: RpRuntimeConfig;
  }
}

type IniConfig = Record<string, Record<string, string>>;

const defaultHost = '0.0.0.0';
const defaultPort = 8080;
const defaultDataDir = resolve(homedir(), '.itw-conformance-tool');

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

function parseIni(iniRaw: string): IniConfig {
  const config: IniConfig = {};
  let currentSection = '';

  for (const rawLine of iniRaw.split(/\r?\n/u)) {
    const line = stripComment(rawLine);
    if (line.length === 0) {
      continue;
    }

    if (line.startsWith('[') && line.endsWith(']')) {
      currentSection = line.slice(1, -1).trim().toLowerCase();
      if (currentSection.length > 0 && config[currentSection] === undefined) {
        config[currentSection] = {};
      }
      continue;
    }

    const separatorIndex = line.indexOf('=');
    if (separatorIndex === -1 || currentSection.length === 0) {
      continue;
    }

    const key = line.slice(0, separatorIndex).trim().toLowerCase();
    const value = line.slice(separatorIndex + 1).trim();
    if (key.length === 0) {
      continue;
    }

    config[currentSection] ??= {};
    config[currentSection][key] = value;
  }

  return config;
}

function parsePort(value: string | undefined, source: string): number {
  if (value === undefined || value.length === 0) {
    return defaultPort;
  }

  const port = Number(value);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    throw new Error(`Invalid rp.port value in ${source}: ${value}`);
  }

  return port;
}

function parsePortOverride(variableName: string): number | undefined {
  const value = process.env[variableName];
  if (value === undefined || value.trim().length === 0) {
    return undefined;
  }

  const parsedPort = Number(value);
  if (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
    throw new Error(`Invalid ${variableName} value: ${value}`);
  }

  return parsedPort;
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

function loadConfigFile(configFilePath: string): IniConfig | undefined {
  if (!existsSync(configFilePath)) {
    return undefined;
  }

  const rawConfig = readFileSync(configFilePath, { encoding: 'utf8' });
  return parseIni(rawConfig);
}

function buildRuntimeConfig(configFilePath: string): RpRuntimeConfig {
  const iniConfig = loadConfigFile(configFilePath);
  const rpSection = iniConfig?.rp;
  const globalSection = iniConfig?.global;

  const port = parsePortOverride('ITW_CT_RP_PORT') ?? parsePort(rpSection?.port, configFilePath);
  const dataDirOverride = process.env.ITW_CT_DATA_DIR;
  const dataDirValue = globalSection?.data_dir;
  const dataDir =
    dataDirOverride !== undefined && dataDirOverride.trim().length > 0
      ? expandHome(dataDirOverride.trim())
      : dataDirValue !== undefined && dataDirValue.trim().length > 0
        ? expandHome(dataDirValue.trim())
        : defaultDataDir;

  return {
    host: defaultHost,
    port,
    baseUrl: `http://localhost:${port}`,
    dataDir,
    configFilePath
  };
}

const envPlugin = fp(async (app) => {
  const configFilePath = resolve(process.cwd(), process.env.ITW_CT_CONFIG_FILE ?? 'config.ini');
  const runtimeConfig = buildRuntimeConfig(configFilePath);

  if (!existsSync(configFilePath)) {
    app.log.warn(
      { configFile: configFilePath, defaultsApplied: { port: defaultPort, dataDir: defaultDataDir } },
      'config.ini not found, using defaults'
    );
  }

  app.decorate('config', runtimeConfig);
});

export default envPlugin;
