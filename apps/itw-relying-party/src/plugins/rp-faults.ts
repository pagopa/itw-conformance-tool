import fp from 'fastify-plugin';

import { createRpFaultStore, type RpFaultStore } from '../faults/rp-fault-store.js';

declare module 'fastify' {
  interface FastifyInstance {
    rpFaultStore: RpFaultStore;
  }
}

export default fp(
  async function rpFaultsPlugin(app) {
    const rpFaultStore = createRpFaultStore();

    app.decorate('rpFaultStore', rpFaultStore);

    app.addHook('onClose', async () => {
      rpFaultStore.clear();
    });
  },
  { name: 'rp-faults' }
);
