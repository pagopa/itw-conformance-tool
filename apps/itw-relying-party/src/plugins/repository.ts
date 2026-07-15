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
  app.decorate('repository', {
    requestObject: new RequestObjectRepository(),
    nonce: new NonceRepository()
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
    const now = Date.now();
    const nonces = app.repository.nonce.list();
    for (const { expiresAt, id } of nonces) {
      if (expiresAt < now) {
        app.repository.nonce.delete(id);
      }
    }
  }, 60000);

  app.addHook('onClose', async () => {
    clearInterval(requestObjectsInterval);
    clearInterval(noncesInterval);
  });
};

export default fp(repositoryPlugin, {
  name: 'repository-plugin'
});
