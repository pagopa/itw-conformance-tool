import z from 'zod';

export const healthCheckResponseSchema = z.object({
  status: z.literal('ok').describe('Service liveness status.')
});

export const getHealthCheckHandler = async () => ({ status: 'ok' });
