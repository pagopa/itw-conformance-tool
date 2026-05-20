import { join } from 'node:path';

import fastifyStatic from '@fastify/static';
import fp from 'fastify-plugin';

export default fp(async (app) => {
  await app.register(fastifyStatic, {
    root: join(import.meta.dirname, '../../assets')
  });
});
