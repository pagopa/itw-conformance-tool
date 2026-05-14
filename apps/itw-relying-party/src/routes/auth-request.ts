import { requestObjectRepository } from '../domain/request-object.js';

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
      }
    },
    handler: async (request, reply) => {
      const { state } = request.params;
      const requestObject = await requestObjectRepository.get(state);
      await requestObjectRepository.update(state, 'checking');
      return reply.code(200).header('content-type', 'application/oauth-authz-req+jwt').send(requestObject.jwt);
    }
  });
};

export default authRequestRoute;
