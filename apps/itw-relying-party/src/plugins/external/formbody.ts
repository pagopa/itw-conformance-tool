import fastifyFormbody from '@fastify/formbody';
import fp from 'fastify-plugin';

export default fp(async (app) => {
  await app.register(fastifyFormbody);
});
