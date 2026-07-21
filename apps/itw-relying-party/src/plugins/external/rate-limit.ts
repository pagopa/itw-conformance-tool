import FastifyRateLimit, { type RateLimitPluginOptions } from '@fastify/rate-limit';

export const autoConfig: RateLimitPluginOptions = {
  global: true,
  max: 100,
  timeWindow: '1 minute'
};

export default FastifyRateLimit;
