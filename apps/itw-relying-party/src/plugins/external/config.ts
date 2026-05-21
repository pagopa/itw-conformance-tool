import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { DatabaseClient, SqliteNonceRepository, SqliteSessionRepository } from '@itw-conformance-tool/database';
import { loadRpConfig, SessionService } from '@itw-conformance-tool/rp';
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

type AuthFile = {
  kty: string;
  x: string;
  y: string;
  crv: string;
  d: string;
  kid: string;
  alg: string;
  use: string;
  key_ops: string[];
};

declare module 'fastify' {
  interface FastifyInstance {
    config: RpConfig;
    rp: {
      authRequestPrivateKeyPem: string;
      authResponsePrivateKeyPem: string;
      basePath: string;
      clientId: string;
      nonceRepository: SqliteNonceRepository;
      sessionService: SessionService;
    };
  }
}

function resolveKeyPath(dataDir: string, keyName: string): string | undefined {
  const candidates = [
    resolve(dataDir, 'rp', `${keyName}.pem`),
    resolve(dataDir, 'rp', keyName),
    resolve(dataDir, `${keyName}.pem`),
    resolve(dataDir, keyName)
  ];

  return candidates.find((candidatePath) => existsSync(candidatePath));
}

async function loadPrivateKey(dataDir: string, keyName: string): Promise<string> {
  const keyPath = resolveKeyPath(dataDir, keyName);

  if (keyPath === undefined) {
    throw new Error(
      `Missing required auth key: ${keyName} not found under ${dataDir} or ${resolve(dataDir, 'rp')}. ` +
        `Please ensure the key file exists before starting the server.`
    );
  }

  const rawKey: AuthFile = await JSON.parse(readFileSync(keyPath, { encoding: 'utf8' }));
  return rawKey.d;
}

const configPlugin = fp(
  async (app) => {
    const configFilePath = resolve(process.cwd(), process.env.ITW_CT_CONFIG_FILE ?? 'config.ini');

    // Load base RP config
    const loadResult = loadRpConfig({ configFilePath });
    const rpConfigFromLib = loadResult.config;
    const dataDir = rpConfigFromLib.dataDir;

    // Load auth keys from data_dir (FR-27)
    let authRequestPrivateKey = '';
    let authResponsePrivateKey = '';

    try {
      authRequestPrivateKey = await loadPrivateKey(dataDir, 'auth-request-key.jwk.json');
      authResponsePrivateKey = await loadPrivateKey(dataDir, 'auth-response-key.jwk.json');
    } catch (err) {
      app.log.error({ err }, 'Failed to load auth keys');
      throw err;
    }

    const runtimeConfig: RpConfig = {
      host: rpConfigFromLib.host,
      port: rpConfigFromLib.port,
      baseUrl: rpConfigFromLib.baseUrl,
      dataDir: rpConfigFromLib.dataDir,
      configFilePath,
      authRequestPrivateKey,
      authResponsePrivateKey
    };

    const databaseClient = new DatabaseClient({ dataDir: runtimeConfig.dataDir });
    const sessionRepository = new SqliteSessionRepository(databaseClient.db);
    const nonceRepository = new SqliteNonceRepository(databaseClient.db);

    const rp = {
      authRequestPrivateKeyPem: runtimeConfig.authRequestPrivateKey,
      authResponsePrivateKeyPem: runtimeConfig.authResponsePrivateKey,
      basePath: runtimeConfig.baseUrl,
      clientId: runtimeConfig.baseUrl,
      nonceRepository,
      sessionService: new SessionService(sessionRepository)
    };

    app.decorate('config', runtimeConfig);
    app.decorate('rp', rp);
    app.addHook('onClose', async () => {
      databaseClient.close();
    });
  },
  { name: 'config' }
);

export default configPlugin;
