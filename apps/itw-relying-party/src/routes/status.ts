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
      const session = await app.sessionService.get(state);
      if (session === undefined) {
        return reply.code(404).send({ message: 'Session not found' });
      }

      const { redirectUri, state: rpState, values } = session;

      if (rpState === 'verified') {
        if (redirectUri === null) {
          await app.sessionService.delete(state);
          return { redirect_uri: 'error.html?response_code=unexpected' };
        }
        return {
          redirect_uri: redirectUri,
          values
        };
      }

      if (rpState === 'rejected') {
        await app.sessionService.delete(state);
        return { redirect_uri: 'rejected-error.html?response_code=rejected' };
      }

      if (rpState === 'denied') {
        await app.sessionService.delete(state);
        return { redirect_uri: 'error.html?response_code=denied' };
      }

      if (rpState === 'expired') {
        await app.sessionService.delete(state);
        return { redirect_uri: 'timeout.html?response_code=expired' };
      }

      if (rpState === 'checking') {
        return { redirect_uri: '?response_code=checking' };
      }

      return { redirect_uri: '?response_code=pending' };
    }
  });
};

export default statusRoute;
