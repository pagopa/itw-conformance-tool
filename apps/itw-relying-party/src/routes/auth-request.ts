import { serveAuthorizationRequestUseCase } from '../use-cases/serve-authorization-request.js';

import type { FastifyPluginAsync } from 'fastify';

interface AuthRequestParams {
  state: string;
}

const authRequestRoute: FastifyPluginAsync = async (app) => {
  app.route<{ Params: AuthRequestParams }>({
    url: '/auth/request/:state',
    method: 'GET',
    schema: {
      tags: ['Relying Party'],
      params: {
        type: 'object',
        required: ['state'],
        properties: {
          state: {
            type: 'string'
          }
        }
      },
      response: {
        200: {
          type: 'string',
          description: 'Signed Request Object JWT'
        },
        404: {
          type: 'object',
          properties: {
            message: { type: 'string' }
          }
        },
        410: {
          type: 'object',
          properties: {
            message: { type: 'string' }
          }
        }
      }
    },
    handler: async (request, reply) => {
      const { state } = request.params;
      const jwt = await serveAuthorizationRequestUseCase({
        state,
        sessionService: app.sessionService
      });
      return reply.code(200).header('content-type', 'application/oauth-authz-req+jwt').send(jwt);
    }
  });
};

export default authRequestRoute;
