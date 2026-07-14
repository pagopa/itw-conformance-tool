import {
  SqliteConformanceSessionRepository,
  SqliteScenarioEventRepository,
  startConformanceCleanupJob
} from '@itw-conformance-tool/conformance';
import { DatabaseClient, SqliteNonceRepository, SqliteSessionRepository } from '@itw-conformance-tool/database';
import { SessionService } from '@itw-conformance-tool/rp';
import fp from 'fastify-plugin';

import type { IConformanceSessionRepository, ScenarioEventSink } from '@itw-conformance-tool/conformance';
import type { INonceRepository, ISessionRepository } from '@itw-conformance-tool/database';

declare module 'fastify' {
  interface FastifyInstance {
    conformanceEventSink: ScenarioEventSink;
    conformanceSessionRepository: IConformanceSessionRepository;
    dbClient: DatabaseClient;
    nonceRepository: INonceRepository;
    sessionRepository: ISessionRepository;
    sessionService: SessionService;
  }
}

export default fp(
  async function dbPlugin(app) {
    const db = new DatabaseClient(app.config.dataDir);
    const sessionRepository = new SqliteSessionRepository(db);
    const nonceRepository = new SqliteNonceRepository(db);

    const conformanceSessionRepository = new SqliteConformanceSessionRepository(db);
    const stopConformanceCleanup = startConformanceCleanupJob({
      logger: app.log,
      repository: conformanceSessionRepository
    });

    app.decorate('dbClient', db);
    app.decorate('conformanceEventSink', new SqliteScenarioEventRepository(db));
    app.decorate('conformanceSessionRepository', conformanceSessionRepository);
    app.decorate('sessionRepository', sessionRepository);
    app.decorate('nonceRepository', nonceRepository);
    app.decorate('sessionService', new SessionService(sessionRepository));

    app.addHook('onClose', () => {
      stopConformanceCleanup();
      db.close();
    });
  },
  { name: 'db', dependencies: ['config'] }
);
