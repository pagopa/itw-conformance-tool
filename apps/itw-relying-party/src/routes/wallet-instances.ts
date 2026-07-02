import {
  extractBearerToken,
  getWalletInstance,
  listWalletInstances,
  revokeWalletInstance
} from '../wallet-provider-backend/service.js';

import type { FastifyPluginAsync } from 'fastify';

const walletInstancesRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/wallet-instances',
    method: 'GET',
    schema: {
      tags: ['Wallet Provider']
    },
    handler: async (request, reply) => {
      const result = listWalletInstances(app.walletProviderBackend, extractBearerToken(request.headers.authorization));
      return reply.code(result.statusCode).header('Content-Type', 'application/json').send(result.body);
    }
  });

  app.route({
    url: '/wallet-instances/:instanceId',
    method: 'GET',
    schema: {
      tags: ['Wallet Provider']
    },
    handler: async (request, reply) => {
      const { instanceId } = request.params as { instanceId: string };
      const result = getWalletInstance(
        app.walletProviderBackend,
        instanceId,
        extractBearerToken(request.headers.authorization)
      );
      return reply.code(result.statusCode).header('Content-Type', 'application/json').send(result.body);
    }
  });

  app.route({
    url: '/wallet-instances/:instanceId',
    method: 'PATCH',
    schema: {
      tags: ['Wallet Provider']
    },
    handler: async (request, reply) => {
      const { instanceId } = request.params as { instanceId: string };
      const body = request.body as { status?: string } | undefined;
      const result = revokeWalletInstance(
        app.walletProviderBackend,
        instanceId,
        extractBearerToken(request.headers.authorization),
        body?.status
      );

      if (result.statusCode === 204) {
        return reply.code(204).send();
      }

      return reply.code(result.statusCode).header('Content-Type', 'application/json').send(result.body);
    }
  });
};

export default walletInstancesRoute;
