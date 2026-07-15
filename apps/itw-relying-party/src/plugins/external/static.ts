import path from 'node:path';

import FastifyStatic, { type FastifyStaticOptions } from '@fastify/static';

export const autoConfig = (): FastifyStaticOptions => ({
  root: path.join(import.meta.dirname, '../..', 'public')
});

/**
 * This plugins allows to serve static files as fast as possible.
 *
 * @see {@link https://github.com/fastify/fastify-static}
 */
export default FastifyStatic;
