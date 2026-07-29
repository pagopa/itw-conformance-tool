import { createHash } from 'node:crypto';

import { createObservedEvent } from '@itw-conformance-tool/conformance';
import { decodeJwt } from 'jose';

import { type StatusListSettings, StatusListService } from '../domain/index.js';
import { STATUS_LIST_TESTED_CREDENTIAL_INDEX } from '../domain/models/status-list.js';
import { makeJwksRepository, makeOauthCallbacks } from '../plugins/index.js';

import type { FastifyPluginAsync } from 'fastify';

const statusListRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/statuslist/1',
    method: 'GET',
    schema: {
      tags: ['Credential']
    },
    handler: async (request, reply) => {
      const { baseURL } = makeOauthCallbacks(app, request);

      try {
        const service = new StatusListService(makeJwksRepository(app));
        const settings: StatusListSettings = app.issuerRuntimeConfigStore.resolveStatusList({
          bits: 1 as const,
          values: [0, 0, 0, 0, 0]
        });
        const jwt = await service.getStatusListJwt(baseURL, settings);
        const payload = decodeJwt(jwt);

        await app.conformanceEventSink?.emit(
          createObservedEvent({
            name: 'issuer.status_list.requested',
            correlationId: request.conformance?.correlation?.correlationId ?? null,
            service: 'credential-issuer',
            requestId: request.id,
            diagnostic: {
              endpoint: '/statuslist/1',
              method: request.method,
              bits: settings.bits,
              credentialIndex: STATUS_LIST_TESTED_CREDENTIAL_INDEX,
              expiresAt: typeof payload.exp === 'number' ? new Date(payload.exp * 1000).toISOString() : undefined,
              statusValue: settings.values[STATUS_LIST_TESTED_CREDENTIAL_INDEX],
              ttlSeconds: settings.ttlSeconds,
              tokenHash: createHash('sha256').update(jwt, 'utf8').digest('base64url')
            }
          })
        );

        return reply.code(200).header('Content-Type', 'application/statuslist+jwt').send(jwt);
      } catch (error) {
        request.log.error({ err: error }, 'Status list generation failed');
        return reply.code(500).send({ error: 'internal_server_error' });
      }
    }
  });
};

export default statusListRoute;
