import { SqliteScenarioEventRepository } from '@itw-conformance-tool/conformance';
import {
  DatabaseClient,
  SqliteDeferredCredentialRepository,
  SqliteNonceRepository,
  SqlitePARRepository,
  SqliteRefreshTokenRepository
} from '@itw-conformance-tool/database';
import fp from 'fastify-plugin';

import type {
  IDeferredCredentialRepository,
  INonceRepository,
  IPARRepository,
  IRefreshTokenRepository,
  ISessionRepository
} from '@itw-conformance-tool/database';

declare module 'fastify' {
  interface FastifyInstance {
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

    const scenarioEventRepository = new SqliteScenarioEventRepository(dbClient);

    app.decorate('conformanceEventSink', scenarioEventRepository);
    app.decorate('dbClient', dbClient);
    app.decorate('nonceRepository', new SqliteNonceRepository(dbClient));
    app.decorate('parRepository', new SqlitePARRepository(dbClient));
    app.decorate('deferredCredentialRepository', new SqliteDeferredCredentialRepository(dbClient));
    app.decorate('refreshTokenRepository', new SqliteRefreshTokenRepository(dbClient));

    app.addHook('onClose', async () => {
      dbClient.close();
    });
  },
  { name: 'db', dependencies: ['config'] }
);
