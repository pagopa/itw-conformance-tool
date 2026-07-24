import fp from 'fastify-plugin';

import { createIssuerFaultStore, type IssuerFaultStore } from '../domain/index.js';

declare module 'fastify' {
  interface FastifyInstance {
    issuerFaultStore: IssuerFaultStore;
  }
}

export default fp(
  async function issuerFaultsPlugin(app) {
    const issuerFaultStore = createIssuerFaultStore();

    app.decorate('issuerFaultStore', issuerFaultStore);

    app.addHook('onClose', async () => {
      issuerFaultStore.clear();
    });
  },
  { name: 'issuer-faults' }
);
