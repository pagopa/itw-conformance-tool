import fp from 'fastify-plugin';

import { createIssuerRuntimeConfigStore, type IssuerRuntimeConfigStore } from '../domain/index.js';

declare module 'fastify' {
  interface FastifyInstance {
    issuerRuntimeConfigStore: IssuerRuntimeConfigStore;
  }
}

export default fp(
  async function issuerRuntimeConfigPlugin(app) {
    const issuerRuntimeConfigStore = createIssuerRuntimeConfigStore();

    app.decorate('issuerRuntimeConfigStore', issuerRuntimeConfigStore);

    app.addHook('onClose', async () => {
      issuerRuntimeConfigStore.clear();
    });
  },
  { name: 'issuer-runtime-config' }
);
