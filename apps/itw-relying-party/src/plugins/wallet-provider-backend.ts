import fp from 'fastify-plugin';

import { createWalletProviderBackendState } from '../wallet-provider-backend/service.js';

import type { WalletProviderBackendState } from '../wallet-provider-backend/types.js';

declare module 'fastify' {
  interface FastifyInstance {
    walletProviderBackend: WalletProviderBackendState;
  }
}

export default fp(
  async function walletProviderBackendPlugin(app) {
    const state = createWalletProviderBackendState({
      baseUrl: app.config.baseUrl,
      keys: {
        federationPrivateKeyPem: app.rpKeys.federationPrivateKeyPem,
        x5cCertPem: app.rpKeys.x5cCertPem
      }
    });

    app.decorate('walletProviderBackend', state);

    app.addHook('onRequest', async (request, reply) => {
      const headers = request.headers as Record<string, unknown>;
      if (headers['x-test-maintenance'] === 'true') {
        return reply
          .code(503)
          .header('Content-Type', 'application/json')
          .send({ error: 'temporarily_unavailable', error_description: 'Service temporarily unavailable' });
      }

      if (headers['x-test-server-error'] === 'true') {
        return reply
          .code(500)
          .header('Content-Type', 'application/json')
          .send({ error: 'server_error', error_description: 'Internal server error' });
      }
    });
  },
  { name: 'wallet-provider-backend', dependencies: ['keys', 'config'] }
);
