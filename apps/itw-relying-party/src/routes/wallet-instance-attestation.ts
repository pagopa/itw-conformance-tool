import { issueWalletAttestationFromRequest } from '../wallet-provider-backend/service.js';

import type { FastifyPluginAsync } from 'fastify';

const walletInstanceAttestationRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/wallet-instance-attestation',
    method: 'POST',
    schema: {
      tags: ['Wallet Provider']
    },
    handler: async (request, reply) => {
      const body = request.body as { assertion?: string } | undefined;
      const headers = request.headers as Record<string, unknown>;
      const result = await issueWalletAttestationFromRequest(app.walletProviderBackend, {
        assertion: body?.assertion ?? '',
        integrityFailHeader: headers['x-test-integrity-fail'] === 'true',
        validationErrorHeader: headers['x-test-validation-error'] === 'true'
      });

      return reply.code(result.statusCode).header('Content-Type', 'application/json').send(result.body);
    }
  });
};

export default walletInstanceAttestationRoute;
