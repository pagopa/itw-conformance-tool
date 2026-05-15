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

function resolvePortOverride(variableName: string): string | undefined {
  const value = process.env[variableName];
  if (value === undefined || value.trim().length === 0) {
    return undefined;
  }

  const parsedPort = Number(value);
  if (!Number.isInteger(parsedPort) || parsedPort < 1 || parsedPort > 65535) {
    throw new Error(`Invalid ${variableName} value: ${value}`);
  }

  return value;
}

export const autoConfig: FastifyEnvOptions = {
  data: {
    PORT: resolvePortOverride('ITW_CT_ISSUER_PORT') ?? process.env.PORT
  },
  schema: z.toJSONSchema(schema, { target: 'draft-07' })
};

export default FastifyEnv;
