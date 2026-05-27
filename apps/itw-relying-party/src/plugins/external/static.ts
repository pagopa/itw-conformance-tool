import { mkdirSync } from 'node:fs';
import { join } from 'node:path';

import fastifyStatic from '@fastify/static';
import fp from 'fastify-plugin';

export default fp(async (app) => {
  const assetsRoot = join(import.meta.dirname, '../../assets');
  mkdirSync(assetsRoot, { recursive: true });
  await app.register(fastifyStatic, {
    root: assetsRoot
  });
});
