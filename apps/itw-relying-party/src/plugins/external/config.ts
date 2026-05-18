import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { loadRpConfig } from '@itw-conformance-tool/rp';
import fp from 'fastify-plugin';

interface RpConfig {
  host: string;
  port: number;
  baseUrl: string;
  dataDir: string;
  configFilePath: string;
  authRequestPrivateKey: string;
  authResponsePrivateKey: string;
}

declare module 'fastify' {
  interface FastifyInstance {
    config: RpConfig;
  }
}

function loadPrivateKey(dataDir: string, keyName: string): string {
  const keyPath = resolve(dataDir, keyName);

  if (!existsSync(keyPath)) {
    throw new Error(
      `Missing required auth key: ${keyName} not found in ${dataDir}. ` +
        `Please ensure the key file exists before starting the server.`
    );
  }

  const key = readFileSync(keyPath, { encoding: 'utf8' });
  if (key.trim().length === 0) {
    throw new Error(
      `Invalid auth key: ${keyName} in ${dataDir} is empty. ` + `Please ensure the key file contains valid content.`
    );
  }

  return key;
}

const configPlugin = fp(async (app) => {
  const configFilePath = resolve(process.cwd(), process.env.ITW_CT_CONFIG_FILE ?? 'config.ini');

  // Load base RP config
  const loadResult = await loadRpConfig({ configFile: configFilePath });
  const rpConfigFromLib = loadResult.config;
  const dataDir = rpConfigFromLib.dataDir;

  // Load auth keys from data_dir (FR-27)
  let authRequestPrivateKey = '';
  let authResponsePrivateKey = '';

  try {
    authRequestPrivateKey = loadPrivateKey(dataDir, 'authRequestPrivateKey');
    authResponsePrivateKey = loadPrivateKey(dataDir, 'authResponsePrivateKey');
  } catch (err) {
    app.log.error({ err }, 'Failed to load auth keys');
    throw err;
  }

  const runtimeConfig: RpConfig = {
    host: rpConfigFromLib.host,
    port: rpConfigFromLib.port,
    baseUrl: rpConfigFromLib.baseUrl ?? loadResult.baseUrl,
    dataDir: rpConfigFromLib.dataDir,
    configFilePath,
    authRequestPrivateKey,
    authResponsePrivateKey
  };

  app.decorate('config', runtimeConfig);
});

export default configPlugin;

