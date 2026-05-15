import {
  DatabaseClient,
  SqliteNonceRepository,
  SqlitePARRepository,
  SqliteSessionRepository
} from '@itw-conformance-tool/database';
import fp from 'fastify-plugin';

import type { INonceRepository, IPARRepository, ISessionRepository } from '@itw-conformance-tool/database';

declare module 'fastify' {
  interface FastifyInstance {
    dbClient: DatabaseClient;
    nonceRepository: INonceRepository;
    parRepository: IPARRepository;
    sessionRepository: ISessionRepository;
  }
}

export default fp(
  async function dbPlugin(app) {
    const dbClient = new DatabaseClient({
      dataDir: app.config.DATA_DIR,
      cleanupIntervalMs: app.config.DB_CLEANUP_INTERVAL_MS
    });

    app.decorate('dbClient', dbClient);
    app.decorate('nonceRepository', new SqliteNonceRepository(dbClient.db));
    app.decorate('parRepository', new SqlitePARRepository(dbClient.db));
    app.decorate('sessionRepository', new SqliteSessionRepository(dbClient.db));

    app.addHook('onClose', async () => {
      dbClient.close();
    });
  },
  { name: 'db', dependencies: ['config'] }
);
