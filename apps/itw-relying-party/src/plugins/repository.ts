import { DatabaseClient } from '@itw-conformance-tool/database';
import fp from 'fastify-plugin';

import { NonceRepository } from '../repository/nonce.js';
import { RequestObjectRepository } from '../repository/request-object.js';

import type { FastifyPluginAsync } from 'fastify';

declare module 'fastify' {
  interface FastifyInstance {
    repository: AppRepository;
  }
}

export interface AppRepository {
  requestObject: RequestObjectRepository;
  nonce: NonceRepository;
}

const repositoryPlugin: FastifyPluginAsync = async (app) => {
  const dbClient = new DatabaseClient(app.config.DATA_DIR);

  app.decorate('repository', {
    requestObject: new RequestObjectRepository(dbClient),
    nonce: new NonceRepository(dbClient)
  });

  const requestObjectsInterval = setInterval(() => {
    const now = Date.now();
    const requestObjects = app.repository.requestObject.list();
    for (const { expiresAt, id } of requestObjects) {
      if (expiresAt < now) {
        app.repository.requestObject.update(id, 'expired');
      }
    }
  }, 10000);

  const noncesInterval = setInterval(() => {
    app.repository.nonce.deleteExpiredNonces();
  }, 60000);

  app.addHook('onClose', async () => {
    clearInterval(requestObjectsInterval);
    clearInterval(noncesInterval);
    dbClient.close();
  });
};

export default fp(repositoryPlugin, {
  name: 'repository-plugin',
  dependencies: ['config']
});
