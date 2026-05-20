import { randomBytes, randomUUID } from 'node:crypto';

import jwt from 'jsonwebtoken';
import { z } from 'zod';

import type { FastifyPluginAsync } from 'fastify';

const TTL_MS = 5 * 60 * 1000;

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

      const state = randomUUID();
      const nonce = randomBytes(32).toString('hex');
      await app.rp.nonceRepository.insert(nonce, Date.now() + TTL_MS);

      const payload = {
        client_id: app.rp.clientId,
        dcql_query: parsed.data.dcqlQuery,
        iss: app.rp.clientId,
        nonce,
        request_uri_method: 'get',
        response_mode: 'direct_post.jwt',
        response_type: 'vp_token',
        response_uri: `${app.rp.basePath}/auth/response`,
        state
      };

      const requestObject = jwt.sign(payload, app.rp.authRequestPrivateKeyPem, {
        algorithm: 'ES256',
        expiresIn: '1h',
        header: {
          alg: 'ES256',
          typ: 'oauth-authz-req+jwt'
        }
      });

      await app.rp.sessionService.create({
        flowType: parsed.data.flowType,
        id: state,
        jwt: requestObject,
        ttlMs: TTL_MS
      });

      const requestUri = `${app.rp.basePath}/auth/request/${state}`;
      const params = new URLSearchParams({
        client_id: app.rp.clientId,
        request_uri: requestUri,
        state
      });
      const walletUrl = new URL(parsed.data.walletAuthBaseUri);
      for (const [key, value] of params.entries()) {
        walletUrl.searchParams.set(key, value);
      }

      return reply.code(200).send({ url: walletUrl.toString() });
    }
  });
};

export default requestObjectRoute;
