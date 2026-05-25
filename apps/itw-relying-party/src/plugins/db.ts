import { DatabaseClient, SqliteNonceRepository, SqliteSessionRepository } from '@itw-conformance-tool/database';
import { SessionService } from '@itw-conformance-tool/rp';
import fp from 'fastify-plugin';

import type { INonceRepository, ISessionRepository } from '@itw-conformance-tool/database';

declare module 'fastify' {
  interface FastifyInstance {
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
    app.decorate('sessionRepository', sessionRepository);
    app.decorate('nonceRepository', nonceRepository);
    app.decorate('sessionService', new SessionService(sessionRepository));

    app.addHook('onClose', async () => {
      await dbClient.close();
    });
  },
  { name: 'db', dependencies: ['config'] }
);
