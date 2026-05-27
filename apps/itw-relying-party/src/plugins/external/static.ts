import { existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';

import fastifyStatic from '@fastify/static';
import fp from 'fastify-plugin';

export default fp(async (app) => {
  const assetsRoot = join(import.meta.dirname, '../../assets');

  if (!existsSync(assetsRoot)) {
    app.log.warn(
      { assetsRoot },
      'Assets directory is missing — static pages (success, error, timeout) will return 404. ' +
        'Run the build or copy src/assets to dist/assets before serving.'
    );
    mkdirSync(assetsRoot, { recursive: true });
  }

  await app.register(fastifyStatic, {
    root: assetsRoot
  });
});
