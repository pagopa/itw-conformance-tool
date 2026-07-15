import FastifyHelmet, { type FastifyHelmetOptions } from '@fastify/helmet';

export const autoConfig: FastifyHelmetOptions = {
  global: true,
  contentSecurityPolicy: {
    directives: {
      'script-src': ["'self'", 'https://cdn.jsdelivr.net', 'https://cdnjs.cloudflare.com', "'unsafe-inline'"]
    }
  }
};

export default FastifyHelmet;
