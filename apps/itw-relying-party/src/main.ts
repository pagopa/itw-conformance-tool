import { logger } from '@itw-conformance-tool/logger';
import closeWithGrace from 'close-with-grace';
import Fastify from 'fastify';
import fp from 'fastify-plugin';

import bootstrap from './app.js';
import { closeRequestObjectStorage, markAsExpired } from './domain/request-object.js';

async function startServer() {
  const app = Fastify({
    loggerInstance: logger,
    // Apply recommended timeouts to prevent slow or idle clients from holding connections open
    connectionTimeout: 120_000,
    requestTimeout: 60_000,
    keepAliveTimeout: 10_000,
    http: {
      headersTimeout: 15_000
    },
    ajv: {
      customOptions: {
        coerceTypes: 'array', // change type of data to match type keyword
        removeAdditional: 'all' // Remove additional body properties
      }
    }
  });

  app.register(fp(bootstrap));

  closeWithGrace(async ({ signal, err }) => {
    if (err) {
      app.log.error({ err }, 'server closing with error');
    } else {
      app.log.info(`${signal} received, server closing`);
    }
    closeRequestObjectStorage();
    await app.close();
  });

  await app.ready();

  setInterval(async () => {
    await markAsExpired();
  }, 10_000);

  // Start server
  try {
    await app.listen({
      host: app.config.host,
      port: app.config.port,
      listenTextResolver: (address) =>
        `IT Wallet Relying Party listening on ${address} (base URL: ${app.config.baseUrl})`
    });
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
}

startServer();
