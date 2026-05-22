import { createPrivateKey, type JsonWebKey } from 'node:crypto';
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

function toPemPrivateKey(raw: string, keyPath: string): string {
  const trimmed = raw.trim();
  if (trimmed.length === 0) {
    throw new Error(`Invalid auth key file: ${keyPath} is empty.`);
  }

  if (trimmed.includes('-----BEGIN') && trimmed.includes('PRIVATE KEY')) {
    return `${trimmed}\n`;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed) as unknown;
  } catch {
    throw new Error(`Invalid auth key format in ${keyPath}: expected PEM or JWK JSON.`);
  }

  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error(`Invalid auth key format in ${keyPath}: expected PEM or JWK JSON object.`);
  }

  try {
    const privateKey = createPrivateKey({ key: parsed as JsonWebKey, format: 'jwk' });
    return privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
  } catch {
    throw new Error(`Invalid JWK private key in ${keyPath}: cannot convert to PEM.`);
  }
}

function loadPrivateKey(dataDir: string, keyName: string): string {
  const keyPath = resolveKeyPath(dataDir, keyName);

  if (keyPath === undefined) {
    throw new Error(
      `Missing required auth key: ${keyName} not found under ${dataDir} or ${resolve(dataDir, 'rp')}. ` +
        `Please ensure the key file exists before starting the server.`
    );
  }

  return toPemPrivateKey(readFileSync(keyPath, { encoding: 'utf8' }), keyPath);
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
      authRequestPrivateKey = loadPrivateKey(dataDir, 'auth-request-key.jwk.json');
      authResponsePrivateKey = loadPrivateKey(dataDir, 'auth-response-key.jwk.json');
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
