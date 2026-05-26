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
      const session = await app.sessionService.get(state);
      if (session === undefined) {
        return reply.code(404).send({ message: 'Session not found' });
      }

      if (session.state === 'expired') {
        return reply.code(404).send({ message: 'Session not found' });
      }

      await app.sessionService.update(state, 'checking');

      return reply.code(200).header('content-type', 'application/oauth-authz-req+jwt').send(session.jwt);
    }
  });
};

export default authRequestRoute;
