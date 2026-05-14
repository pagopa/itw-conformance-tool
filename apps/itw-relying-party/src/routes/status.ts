import { requestObjectRepository } from '../domain/request-object.js';

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
    handler: async (request) => {
      const { state } = request.params;
      const { redirectUri, status, values } = await requestObjectRepository.get(state);

      if (status === 'verified') {
        if (redirectUri === undefined) {
          await requestObjectRepository.delete(state);
          return { redirect_uri: 'error.html?response_code=unexpected' };
        }
        return {
          redirect_uri: `${redirectUri}?response_code=success`,
          values
        };
      }

      if (status === 'rejected') {
        await requestObjectRepository.delete(state);
        return { redirect_uri: 'rejected-error.html?response_code=rejected' };
      }

      if (status === 'denied') {
        await requestObjectRepository.delete(state);
        return { redirect_uri: 'error.html?response_code=denied' };
      }

      if (status === 'expired') {
        await requestObjectRepository.delete(state);
        return { redirect_uri: 'timeout.html?response_code=expired' };
      }

      if (status === 'checking') {
        return { redirect_uri: '?response_code=checking' };
      }

      return { redirect_uri: '?response_code=pending' };
    }
  });
};

export default statusRoute;
