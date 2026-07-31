import { createObservedEvent } from '@itw-conformance-tool/conformance';
import z from 'zod';

import type { FastifyReply, FastifyRequest } from 'fastify';

export const getErasureQuerystringSchema = z.object({
  callback_url: z
    .string()
    .url()
    .regex(/^https:\/\//, 'callback_url must use HTTPS')
    .optional()
    .describe('Optional HTTPS callback URL.')
});

export const getErasureResponseSchema = z.object({
  status: z.literal('accepted')
});

export type GetErasureQuerystring = z.infer<typeof getErasureQuerystringSchema>;

export const getErasureHandler = async (
  req: FastifyRequest<{ Querystring: GetErasureQuerystring }>,
  reply: FastifyReply
): Promise<FastifyReply> => {
  await req.server.conformanceEventSink.emit(
    createObservedEvent({
      name: 'rp.erasure.requested',
      correlationId: null,
      service: 'relying-party',
      requestId: req.id,
      diagnostic: {
        callbackUrlPresent: typeof req.query.callback_url === 'string',
        endpoint: '/erasure',
        method: req.method,
        outcome: 'accepted'
      }
    })
  );

  return reply.code(202).type('application/json').send({ status: 'accepted' });
};
