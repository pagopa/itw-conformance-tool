import { registerAuthRequestConformanceHooks } from '../hooks/conformance.js';
import { serveAuthorizationRequestUseCase } from '../use-cases/serve-authorization-request.js';

import type { FastifyPluginAsync } from 'fastify';

interface AuthRequestParams {
  state: string;
}

interface PostAuthRequestBody {
  wallet_metadata?: string;
  wallet_nonce?: string;
}

const authRequestRoute: FastifyPluginAsync = async (app) => {
  registerAuthRequestConformanceHooks(app);

  const routeSchema = {
    tags: ['Relying Party'],
    params: {
      type: 'object',
      required: ['state'],
      properties: { state: { type: 'string' } }
    },
    response: {
      200: { type: 'string', description: 'Signed Request Object JWT' },
      400: { type: 'object', properties: { message: { type: 'string' } } },
      404: { type: 'object', properties: { message: { type: 'string' } } },
      410: { type: 'object', properties: { message: { type: 'string' } } }
    }
  };

  // WP_082: wallet retrieves the signed Request Object JWT via GET
  app.route<{ Params: AuthRequestParams }>({
    url: '/auth/request/:state',
    method: 'GET',
    schema: routeSchema,
    handler: async (request, reply) => {
      const { state } = request.params;
      const jwt = await serveAuthorizationRequestUseCase({ state, sessionService: app.sessionService });
      return reply.code(200).header('content-type', 'application/oauth-authz-req+jwt').send(jwt);
    }
  });

  // WP_083: wallet-initiated flow — wallet POSTs wallet_metadata + wallet_nonce
  app.route<{ Params: AuthRequestParams; Body: PostAuthRequestBody }>({
    url: '/auth/request/:state',
    method: 'POST',
    schema: {
      ...routeSchema,
      consumes: ['application/x-www-form-urlencoded'],
      body: {
        type: 'object',
        properties: {
          wallet_metadata: { type: 'string' },
          wallet_nonce: { type: 'string' }
        }
      }
    },
    handler: async (request, reply) => {
      const { state } = request.params;
      const jwt = await serveAuthorizationRequestUseCase({ state, sessionService: app.sessionService });
      return reply.code(200).header('content-type', 'application/oauth-authz-req+jwt').send(jwt);
    }
  });
};

export default authRequestRoute;
