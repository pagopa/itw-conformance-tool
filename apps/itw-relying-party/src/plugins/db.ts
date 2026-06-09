import { SqliteConformanceSessionRepository } from '@itw-conformance-tool/conformance';
import { DatabaseClient, SqliteNonceRepository, SqliteSessionRepository } from '@itw-conformance-tool/database';
import { SessionService } from '@itw-conformance-tool/rp';
import fp from 'fastify-plugin';

import type { IConformanceSessionRepository } from '@itw-conformance-tool/conformance';
import type { INonceRepository, ISessionRepository } from '@itw-conformance-tool/database';

declare module 'fastify' {
  interface FastifyInstance {
    conformanceSessionRepository: IConformanceSessionRepository;
    dbClient: DatabaseClient;
    nonceRepository: INonceRepository;
    sessionRepository: ISessionRepository;
    sessionService: SessionService;
  }
}

export default fp(
  async function dbPlugin(app) {
    const dbClient = new DatabaseClient({ dataDir: app.config.dataDir });
    const sessionRepository = new SqliteSessionRepository(dbClient.db);
    const nonceRepository = new SqliteNonceRepository(dbClient.db);

    app.decorate('dbClient', dbClient);
    app.decorate('conformanceSessionRepository', new SqliteConformanceSessionRepository(dbClient.db));
    app.decorate('sessionRepository', sessionRepository);
    app.decorate('nonceRepository', nonceRepository);
    app.decorate('sessionService', new SessionService(sessionRepository));

    app.addHook('onClose', () => {
      dbClient.close();
    });
  },
  { name: 'db', dependencies: ['config'] }
);
