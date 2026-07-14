import {
  SqliteConformanceSessionRepository,
  SqliteScenarioEventRepository,
  startConformanceCleanupJob
} from '@itw-conformance-tool/conformance';
import {
  DatabaseClient,
  SqliteNonceRepository,
  SqlitePARRepository,
  SqliteSessionRepository
} from '@itw-conformance-tool/database';
import fp from 'fastify-plugin';

import type { IConformanceSessionRepository } from '@itw-conformance-tool/conformance';
import type { INonceRepository, IPARRepository, ISessionRepository } from '@itw-conformance-tool/database';

declare module 'fastify' {
  interface FastifyInstance {
    conformanceSessionRepository: IConformanceSessionRepository;
    dbClient: DatabaseClient;
    nonceRepository: INonceRepository;
    parRepository: IPARRepository;
    sessionRepository: ISessionRepository;
  }
}

export default fp(
  async function dbPlugin(app) {
    const dbClient = new DatabaseClient(app.config.DATA_DIR);

    const conformanceSessionRepository = new SqliteConformanceSessionRepository(dbClient.raw);
    const scenarioEventRepository = new SqliteScenarioEventRepository(dbClient.raw);
    const stopConformanceCleanup = startConformanceCleanupJob({
      logger: app.log,
      repository: conformanceSessionRepository
    });

    app.decorate('conformanceSessionRepository', conformanceSessionRepository);
    app.decorate('conformanceEventSink', scenarioEventRepository);
    app.decorate('dbClient', dbClient);
    app.decorate('nonceRepository', new SqliteNonceRepository(dbClient.raw));
    app.decorate('parRepository', new SqlitePARRepository(dbClient.raw));
    app.decorate('sessionRepository', new SqliteSessionRepository(dbClient.raw));

    app.addHook('onClose', async () => {
      stopConformanceCleanup();
      await dbClient.close();
    });
  },
  { name: 'db', dependencies: ['config'] }
);
