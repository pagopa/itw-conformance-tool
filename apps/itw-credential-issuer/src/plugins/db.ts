import {
  SqliteConformanceSessionRepository,
  SqliteScenarioEventRepository,
  startConformanceCleanupJob
} from '@itw-conformance-tool/conformance';
import {
  DatabaseClient,
  SqliteDeferredCredentialRepository,
  SqliteNonceRepository,
  SqlitePARRepository,
  SqliteRefreshTokenRepository,
  SqliteSessionRepository
} from '@itw-conformance-tool/database';
import fp from 'fastify-plugin';

import type { IConformanceSessionRepository } from '@itw-conformance-tool/conformance';
import type {
  IDeferredCredentialRepository,
  INonceRepository,
  IPARRepository,
  IRefreshTokenRepository,
  ISessionRepository
} from '@itw-conformance-tool/database';

declare module 'fastify' {
  interface FastifyInstance {
    conformanceSessionRepository: IConformanceSessionRepository;
    dbClient: DatabaseClient;
    deferredCredentialRepository: IDeferredCredentialRepository;
    nonceRepository: INonceRepository;
    parRepository: IPARRepository;
    refreshTokenRepository: IRefreshTokenRepository;
    sessionRepository: ISessionRepository;
  }
}

export default fp(
  async function dbPlugin(app) {
    const dbClient = new DatabaseClient(app.config.DATA_DIR);

    const conformanceSessionRepository = new SqliteConformanceSessionRepository(dbClient);
    const scenarioEventRepository = new SqliteScenarioEventRepository(dbClient);
    const stopConformanceCleanup = startConformanceCleanupJob({
      logger: app.log,
      repository: conformanceSessionRepository
    });

    app.decorate('conformanceSessionRepository', conformanceSessionRepository);
    app.decorate('conformanceEventSink', scenarioEventRepository);
    app.decorate('dbClient', dbClient);
    app.decorate('nonceRepository', new SqliteNonceRepository(dbClient));
    app.decorate('parRepository', new SqlitePARRepository(dbClient));
    app.decorate('sessionRepository', new SqliteSessionRepository(dbClient));
    app.decorate('deferredCredentialRepository', new SqliteDeferredCredentialRepository(dbClient));
    app.decorate('refreshTokenRepository', new SqliteRefreshTokenRepository(dbClient));

    app.addHook('onClose', async () => {
      stopConformanceCleanup();
      await dbClient.close();
    });
  },
  { name: 'db', dependencies: ['config'] }
);
