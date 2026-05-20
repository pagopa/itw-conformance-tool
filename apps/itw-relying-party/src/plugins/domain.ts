import { existsSync } from 'node:fs';

import { type FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';

import { SqliteNonceRepository, SqliteSessionRepository } from '../infrastructure/index.js';

import type { INonceRepository, ISessionRepository } from '@itw-conformance-tool/database';

declare module 'fastify' {
  interface FastifyInstance {
    sessionRepository: ISessionRepository;
    nonceRepository: INonceRepository;
  }
}

/**
 * Plugin that initializes and wires up domain repositories for dependency injection.
 * Creates SQLite-backed implementations of SessionRepository and NonceRepository.
 */
const domainPlugin = fp(
  async (app: FastifyInstance) => {
    const dataDir = app.config.dataDir;

    // Verify data directory exists and is accessible
    if (!existsSync(dataDir)) {
      app.log.warn({ dataDir }, 'Data directory does not exist, will be created on first use');
    }

    // Initialize repositories
    const sessionRepository = new SqliteSessionRepository(dataDir);
    const nonceRepository = new SqliteNonceRepository(dataDir);

    // Register with Fastify for graceful shutdown
    app.addHook('onClose', async () => {
      app.log.info('Closing repositories');
      sessionRepository.close();
      nonceRepository.close();
    });

    // Decorate app with repositories for use in routes and services
    app.decorate('sessionRepository', sessionRepository);
    app.decorate('nonceRepository', nonceRepository);

    app.log.info('Domain repositories initialized and wired');
  },
  {
    name: 'domain',
    dependencies: ['configPlugin']
  }
);

export default domainPlugin;
