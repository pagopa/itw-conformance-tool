import path from 'node:path';

import FastifyEnv from '@fastify/env';
import fp from 'fastify-plugin';
import { z } from 'zod';

declare module 'fastify' {
  interface FastifyInstance {
    config: {
      BASE_URL: string;
      DATA_DIR: string;
      AUTH_FLOW: 'direct' | 'l2plus' | 'l3';
    };
  }
}

const AUTH_FLOW_VALUES = ['direct', 'l2plus', 'l3'] as const;

const schema = z.object({
  BASE_URL: z.string().default('https://localhost:3000'),
  DATA_DIR: z.string().default(path.resolve(process.cwd(), '.itw-conformance-tool')),
  AUTH_FLOW: z.enum(AUTH_FLOW_VALUES).default('direct')
});

export default fp(
  async function configPlugin(app) {
    const processEnv: NodeJS.ProcessEnv = { ...process.env };

    const data = schema.parse(processEnv);
    const port = process.env.ITW_CT_ISSUER_PORT || 3000;

    data.BASE_URL = `https://localhost:${port}`;
    data.DATA_DIR = path.join(process.env.ITW_CT_DATA_DIR as string);
    data.AUTH_FLOW = (process.env.ITW_CT_ISSUER_AUTH_FLOW as (typeof AUTH_FLOW_VALUES)[number]) || 'direct';

    await app.register(FastifyEnv, {
      confKey: 'config',
      data,
      schema: z.toJSONSchema(schema, { target: 'draft-07' })
    });
  },

  { name: 'config' }
);
