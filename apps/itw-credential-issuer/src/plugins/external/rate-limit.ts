import FastifyRateLimit, { type RateLimitPluginOptions } from '@fastify/rate-limit';

export const autoConfig: RateLimitPluginOptions = {
  global: false
};

export default FastifyRateLimit;
