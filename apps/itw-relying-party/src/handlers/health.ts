import z from 'zod';

import type { FastifyReply, FastifyRequest } from 'fastify';

export const healthCheckResponseSchema = z.object({
  status: z.literal('ok').describe('Service liveness status.')
});

export const getHealthCheckHandler = async (_req: FastifyRequest, res: FastifyReply): Promise<FastifyReply> => {
  return res.status(200).send({ status: 'ok' });
};
