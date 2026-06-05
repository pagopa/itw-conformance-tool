import path from 'node:path';

import FastifyEnv from '@fastify/env';
import fp from 'fastify-plugin';
import { z } from 'zod';

declare module 'fastify' {
  interface FastifyInstance {
    config: {
      BASE_URL_SCHEME: 'http' | 'https';
      HOST: string;
      PORT: number;
      DATA_DIR: string;
      DB_CLEANUP_INTERVAL_MS: number;
      AUTH_FLOW: 'direct' | 'l2plus' | 'l3';
      HTTPS_ENABLED: boolean;
      TLS_CERT_PATH: string;
      TLS_KEY_PATH: string;
    };
  }
}

const AUTH_FLOW_VALUES = ['direct', 'l2plus', 'l3'] as const;

const schema = z.object({
  BASE_URL_SCHEME: z.enum(['http', 'https']).default('http'),
  HOST: z.string().default('localhost'),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  DATA_DIR: z.string().default(path.join(process.cwd(), '.itw-conformance-tool')),
  DB_CLEANUP_INTERVAL_MS: z.coerce.number().int().positive().default(60_000),
  AUTH_FLOW: z.enum(AUTH_FLOW_VALUES).default('direct'),
  HTTPS_ENABLED: z.coerce.boolean().default(false),
  TLS_CERT_PATH: z.string().default(''),
  TLS_KEY_PATH: z.string().default('')
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

    const orchestratedHttpsEnabled = resolvePathOverride('ITW_CT_HTTPS');
    if (orchestratedHttpsEnabled !== undefined && data.HTTPS_ENABLED === undefined) {
      const normalized = orchestratedHttpsEnabled.toLowerCase();
      data.HTTPS_ENABLED = normalized === 'true' || normalized === '1' ? 'true' : 'false';
    }

    if (!data.BASE_URL_SCHEME) {
      const httpsEnabledValue = (data.HTTPS_ENABLED ?? '').trim().toLowerCase();
      if (httpsEnabledValue === 'true' || httpsEnabledValue === '1') {
        data.BASE_URL_SCHEME = 'https';
      }
    }

    const orchestratedTlsCertPath = resolvePathOverride('ITW_CT_TLS_CERT_PATH');
    if (orchestratedTlsCertPath !== undefined) {
      data.TLS_CERT_PATH = orchestratedTlsCertPath;
    }

    const orchestratedTlsKeyPath = resolvePathOverride('ITW_CT_TLS_KEY_PATH');
    if (orchestratedTlsKeyPath !== undefined) {
      data.TLS_KEY_PATH = orchestratedTlsKeyPath;
    }

    await app.register(FastifyEnv, {
      confKey: 'config',
      data,
      schema: z.toJSONSchema(schema, { target: 'draft-07' })
    });
  },
  { name: 'config' }
);
