import FastifyRateLimit from '@fastify/rate-limit';
import Fastify from 'fastify';

import type { FastifyPluginAsync } from 'fastify';

const signingKey = {
  alg: 'ES256',
  crv: 'P-256',
  d: 'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY',
  kid: 'issuer-sign-key',
  kty: 'EC' as const,
  x: 'f83OJ3D2xF4x6xw5vM90oCbGyF_F7fsRG3Gzdh0dX8Q',
  y: 'x_FEzRu9h4M5xYfZfbQ3VIAtF_forNCz7L3A5kZZgU8'
};

export async function buildRouteApp(route: FastifyPluginAsync) {
  const app = Fastify();

  app.decorate('config', {
    HOST: 'localhost',
    PORT: 3000,
    DATA_DIR: '/tmp',
    DB_CLEANUP_INTERVAL_MS: 60_000,
    AUTH_FLOW: 'l2plus'
  });

  app.decorate('issuerKeys', {
    signingKeysJwks: JSON.stringify({ keys: [signingKey] }),
    iacaCertPem: '-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----\n',
    iacaKeyPem: '-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n'
  });

  app.decorate('nonceRepository', {
    consume: async () => true,
    delete: async () => undefined,
    get: async () => undefined,
    insert: async () => undefined
  });

  app.decorate('parRepository', {
    delete: async () => undefined,
    get: async () => undefined,
    insert: async () => undefined,
    update: async () => undefined
  });

  app.decorate('sessionRepository', {
    delete: async () => undefined,
    get: async () => undefined,
    insert: async () => undefined,
    update: async () => undefined
  });

  app.decorate('dbClient', {
    db: {
      prepare: () => ({
        get: () => undefined,
        run: () => ({ changes: 0, lastInsertRowid: 0 })
      })
    }
  } as never);

  await app.register(FastifyRateLimit, { global: false });
  await app.register(route);
  await app.ready();

  return app;
}
