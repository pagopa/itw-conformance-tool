import { SessionNotFoundError, getPresentationStatusUseCase } from '../use-cases/get-presentation-status.js';

import type { FastifyPluginAsync } from 'fastify';

interface StatusParams {
  state: string;
}

const statusRoute: FastifyPluginAsync = async (app) => {
  app.route<{ Params: StatusParams }>({
    url: '/status/:state',
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
      try {
        const result = await getPresentationStatusUseCase({
          state,
          sessionService: app.sessionService
        });

        return reply.code(200).send(result);
      } catch (error) {
        if (error instanceof SessionNotFoundError) {
          return reply.code(404).send({ message: 'Session not found' });
        }

        throw error;
      }
    }
  });
};

export default statusRoute;
