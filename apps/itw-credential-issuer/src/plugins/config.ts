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
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  DATA_DIR: z.string().default(path.join(process.cwd(), '.itw-conformance-tool', 'issuer')),
  DB_CLEANUP_INTERVAL_MS: z.coerce.number().int().positive().default(60_000),
  KEYS_DIR: z.string().optional()
});

function resolveIssuerDataDir(globalDataDir: string): string {
  const trimmed = globalDataDir.trim();
  if (trimmed.length === 0) {
    return trimmed;
  }

  return path.basename(trimmed) === 'issuer' ? trimmed : path.join(trimmed, 'issuer');
}

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

export default fp(
  async function configPlugin(app) {
    const data: NodeJS.ProcessEnv = { ...process.env };
    const orchestratedPort = resolvePortOverride('ITW_CT_ISSUER_PORT');
    if (orchestratedPort !== undefined) {
      data.PORT = orchestratedPort;
    }

    if (data.ITW_CT_DATA_DIR && !data.DATA_DIR) {
      data.DATA_DIR = resolveIssuerDataDir(data.ITW_CT_DATA_DIR);
    }

    await app.register(FastifyEnv, {
      confKey: 'config',
      data,
      schema: z.toJSONSchema(schema, { target: 'draft-07' })
    });
  },
  { name: 'config' }
);
