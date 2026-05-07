import FastifyEnv, { type FastifyEnvOptions } from '@fastify/env';
import { z } from 'zod';

declare module 'fastify' {
  interface FastifyInstance {
    config: {
      HOST: string;
      PORT: number;
    };
  }
}

const schema = z.object({
  HOST: z.string().default('localhost'),
  PORT: z.number().default(3000)
});

export const autoConfig: FastifyEnvOptions = {
  schema: z.toJSONSchema(schema, { target: 'draft-07' })
};

export default FastifyEnv;
