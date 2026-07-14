import { createObservedEvent, extractRpSessionId } from '@itw-conformance-tool/conformance';

import { registerAuthRequestConformanceHooks } from '../hooks/conformance.js';
import { serveAuthorizationRequestUseCase } from '../use-cases/serve-authorization-request.js';

import type { FastifyPluginAsync } from 'fastify';

interface AuthRequestParams {
  state: string;
}

const authRequestRoute: FastifyPluginAsync = async (app) => {
  registerAuthRequestConformanceHooks(app);

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
      const sessionId = extractRpSessionId(state);

      try {
        await app.conformanceEventSink.emit(
          createObservedEvent({
            name: 'rp.request_object.requested',
            scenarioId: null,
            correlationId: sessionId,
            service: 'relying-party',
            requestId: request.id,
            diagnostic: { state }
          })
        );
      } catch (error) {
        request.log.warn({ err: error, state }, 'Failed to emit conformance RP request object event');
      }

      const jwt = await serveAuthorizationRequestUseCase({
        state,
        sessionService: app.sessionService
      });
      return reply.code(200).header('content-type', 'application/oauth-authz-req+jwt').send(jwt);
    }
  });
};

export default authRequestRoute;
