import { createHttpsOptions } from '@itw-conformance-tool/crypto';
import { attachServiceIpcAdapter } from '@itw-conformance-tool/ipc';
import { logger } from '@itw-conformance-tool/logger';
import closeWithGrace from 'close-with-grace';
import Fastify from 'fastify';
import fp from 'fastify-plugin';

import bootstrap from './app.js';

async function startServer() {
  const app = Fastify({
    connectionTimeout: 120_000,
    requestTimeout: 60_000,
    keepAliveTimeout: 10_000,
    https: await createHttpsOptions(),
    loggerInstance: logger,
    ajv: {
      customOptions: {
        coerceTypes: 'array',
        removeAdditional: 'all'
      }
    }
  });

  app.server.headersTimeout = 15_000;

  app.register(fp(bootstrap));

  closeWithGrace(async ({ signal, err }) => {
    if (err) {
      app.log.error({ err }, 'server closing with error');
    } else if (signal) {
      app.log.info(`${signal} received, server closing`);
    }
    await app.close();
  });

  await app.ready();
  app.server.headersTimeout = 15_000;

  const url = new URL(app.config.BASE_URL);

  try {
    await app.listen({
      host: url.hostname,
      port: Number(url.port),
      listenTextResolver: (address) => `IT Wallet Provider listening on ${address}`
    });
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }

  attachServiceIpcAdapter({
    endpoint: app.config.BASE_URL,
    service: 'wallet-provider',
    stop: () => app.close()
  });
}

startServer();
