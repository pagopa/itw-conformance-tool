import path from 'node:path';

import FastifyStatic, { type FastifyStaticOptions } from '@fastify/static';

export const autoConfig = (): FastifyStaticOptions => {
  const dirPath = path.join(import.meta.dirname, '../../..', 'public');

  return {
    root: dirPath
  };
};

/**
 * This plugins allows to serve static files as fast as possible.
 *
 * @see {@link https://github.com/fastify/fastify-static}
 */
export default FastifyStatic;
