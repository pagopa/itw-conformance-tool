import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { DatabaseClient, SqliteNonceRepository, SqliteSessionRepository } from '@itw-conformance-tool/database';
import { DEFAULT_DATA_DIR, DEFAULT_PORT, loadRpConfig, type RpConfig } from '@itw-conformance-tool/rp';
import { SessionService } from '@itw-conformance-tool/rp';
import fp from 'fastify-plugin';

interface RpRuntimeContext {
  authRequestPrivateKeyPem: string;
  authResponsePrivateKeyPem: string;
  basePath: string;
  clientId: string;
  nonceRepository: SqliteNonceRepository;
  sessionService: SessionService;
}

declare module 'fastify' {
  interface FastifyInstance {
    config: RpConfig;
    rp: RpRuntimeContext;
  }
}

function normalizePrivateKey(content: string): string {
  const trimmed = content.trim();
  if (trimmed.includes('-----BEGIN')) {
    return trimmed;
  }
  return Buffer.from(trimmed, 'base64').toString('utf8').trim();
}

function readRequiredKey(dataDir: string, fileName: string): string {
  const candidates = [join(dataDir, 'rp', fileName), join(dataDir, fileName)];

  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      return normalizePrivateKey(readFileSync(candidate, { encoding: 'utf8' }));
    }
  }

  throw new Error(`Missing required key file "${fileName}" in ${candidates.join(' or ')}`);
}

const envPlugin = fp(async (app) => {
  const configFilePath = resolve(process.cwd(), process.env.ITW_CT_CONFIG_FILE ?? 'config.ini');
  const { config, configFileFound } = loadRpConfig({ configFilePath });

  if (!configFileFound) {
    app.log.warn(
      { configFile: configFilePath, defaultsApplied: { port: DEFAULT_PORT, dataDir: DEFAULT_DATA_DIR } },
      'config.ini not found, using defaults'
    );
  }

  const databaseClient = new DatabaseClient({ dataDir: config.dataDir });
  const sessionRepository = new SqliteSessionRepository(databaseClient.db);
  const nonceRepository = new SqliteNonceRepository(databaseClient.db);

  const rp: RpRuntimeContext = {
    authRequestPrivateKeyPem: readRequiredKey(config.dataDir, 'auth-request-private-key.pem'),
    authResponsePrivateKeyPem: readRequiredKey(config.dataDir, 'auth-response-private-key.pem'),
    basePath: config.baseUrl,
    clientId: config.baseUrl,
    nonceRepository,
    sessionService: new SessionService(sessionRepository)
  };

  app.decorate('config', config);
  app.decorate('rp', rp);
  app.addHook('onClose', async () => {
    databaseClient.close();
  });
});

function resolvePortOverride(variableName: string): string | undefined {
  const value = process.env[variableName];
  if (value === undefined || value.trim().length === 0) {
    return undefined;
  }

  const parsedPort = Number(value);
  if (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
    throw new Error(`Invalid ${variableName} value: ${value}`);
  }

  return value;
}

export const autoConfig: FastifyEnvOptions = {
  data: {
    PORT: resolvePortOverride('ITW_CT_RP_PORT') ?? process.env.PORT
  },
  schema: z.toJSONSchema(schema, { target: 'draft-07' })
};

export default FastifyEnv;
