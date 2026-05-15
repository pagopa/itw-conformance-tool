import path from 'node:path';

import FastifyEnv from '@fastify/env';
import fp from 'fastify-plugin';
import { z } from 'zod';

declare module 'fastify' {
  interface FastifyInstance {
    config: {
      HOST: string;
      PORT: number;
      DATA_DIR: string;
      DB_CLEANUP_INTERVAL_MS: number;
      KEYS_DIR?: string;
    };
  }
}

const schema = z.object({
  HOST: z.string().default('localhost'),
  PORT: z.coerce.number().int().positive().default(3000),
  DATA_DIR: z.string().default(path.join(process.cwd(), '.data', 'itw-credential-issuer')),
  DB_CLEANUP_INTERVAL_MS: z.coerce.number().int().positive().default(60_000),
  KEYS_DIR: z.string().optional()
});

export default fp(
  async function configPlugin(app) {
    await app.register(FastifyEnv, {
      confKey: 'config',
      schema: z.toJSONSchema(schema, { target: 'draft-07' })
    });
  },
  { name: 'config' }
);
