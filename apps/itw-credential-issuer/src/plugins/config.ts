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
      AUTH_FLOW: 'direct' | 'l2plus' | 'l3';
    };
  }
}

const AUTH_FLOW_VALUES = ['direct', 'l2plus', 'l3'] as const;

const schema = z.object({
  HOST: z.string().default('localhost'),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  DATA_DIR: z.string().default(path.join(process.cwd(), '.itw-conformance-tool')),
  DB_CLEANUP_INTERVAL_MS: z.coerce.number().int().positive().default(60_000),
  AUTH_FLOW: z.enum(AUTH_FLOW_VALUES).default('direct')
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

function resolvePathOverride(variableName: string): string | undefined {
  const value = process.env[variableName];
  if (value === undefined || value.trim().length === 0) {
    return undefined;
  }

  return value.trim();
}

export default fp(
  async function configPlugin(app) {
    const data: NodeJS.ProcessEnv = { ...process.env };
    const orchestratedPort = resolvePortOverride('ITW_CT_ISSUER_PORT');
    if (orchestratedPort !== undefined) {
      data.PORT = orchestratedPort;
    }
    const orchestratedDataDir = resolvePathOverride('ITW_CT_DATA_DIR');
    if (orchestratedDataDir !== undefined) {
      data.DATA_DIR = path.join(orchestratedDataDir);
    }

    if (data.ITW_CT_ISSUER_AUTH_FLOW && !data.AUTH_FLOW) {
      data.AUTH_FLOW = data.ITW_CT_ISSUER_AUTH_FLOW;
    }

    await app.register(FastifyEnv, {
      confKey: 'config',
      data,
      schema: z.toJSONSchema(schema, { target: 'draft-07' })
    });
  },
  { name: 'config' }
);
