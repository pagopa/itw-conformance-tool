import { z } from 'zod';

import { createAuthorizationRequestUseCase } from '../use-cases/create-authorization-request.js';

import type { FastifyPluginAsync } from 'fastify';

const authorizationRequestSchema = z
  .object({
    dcqlQuery: z.object({
      credential_sets: z
        .array(
          z.object({
            options: z.array(z.array(z.string())),
            purpose: z.union([z.string(), z.number(), z.record(z.string(), z.any())]).optional(),
            required: z.boolean().optional()
          })
        )
        .optional(),
      credentials: z.array(
        z.object({
          claim_sets: z.array(z.array(z.string())).optional(),
          claims: z
            .array(
              z.object({
                id: z.string().optional(),
                path: z.array(z.string()),
                values: z.array(z.union([z.string(), z.number(), z.boolean()])).optional()
              })
            )
            .optional(),
          format: z.enum(['vc+sd-jwt', 'dc+sd-jwt']),
          id: z.string(),
          meta: z.object({ vct_values: z.array(z.string()) }).optional()
        })
      )
    }),
    flow_type: z.enum(['same-device', 'cross-device']),
    wallet_auth_base_uri: z.string().trim().min(1).url().default('https://continua.io.pagopa.it/itw/auth')
  })
  .transform(({ dcqlQuery, flow_type, wallet_auth_base_uri }) => ({
    dcqlQuery,
    flowType: flow_type,
    walletAuthBaseUri: wallet_auth_base_uri
  }));

const requestObjectRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/request-object',
    method: 'POST',
    schema: {
      tags: ['Relying Party']
    },
    handler: async (request, reply) => {
      const parsed = authorizationRequestSchema.safeParse(request.body);
      if (!parsed.success) {
        return reply.code(400).send({ message: 'DCQL is not correct' });
      }

      const result = await createAuthorizationRequestUseCase({
        baseUrl: app.config.baseUrl,
        entityId: app.config.entityId,
        dcqlQuery: parsed.data.dcqlQuery,
        flowType: parsed.data.flowType,
        nonceRepository: app.nonceRepository,
        rpKeys: app.rpKeys,
        sdkConfig: app.sdkConfig,
        sessionService: app.sessionService,
        walletAuthBaseUri: parsed.data.walletAuthBaseUri
      });

      if (app.hasDecorator('conformanceSessionRepository')) {
        try {
          await app.conformanceSessionRepository.create({
            sessionId: result.state,
            startedAt: new Date().toISOString(),
            status: 'OPEN',
            checks: []
          });
        } catch (err) {
          app.log.warn({ err, sessionId: result.state }, 'conformance: failed to open session at request-object');
        }
      }

      return reply.code(200).send({ url: result.walletUrl });
    }
  });
};

export default requestObjectRoute;
