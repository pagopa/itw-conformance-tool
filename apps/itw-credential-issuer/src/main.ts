import { createHttpsOptions } from '@itw-conformance-tool/crypto';
import { attachServiceIpcAdapter } from '@itw-conformance-tool/ipc';
import { logger } from '@itw-conformance-tool/logger';
import closeWithGrace from 'close-with-grace';
import Fastify from 'fastify';
import fp from 'fastify-plugin';
import open from 'open';

import bootstrap from './app.js';

async function startServer() {
  const app = Fastify({
    connectionTimeout: 120_000,
    // 1 minute: suitable for most payloads, including moderate file uploads
    requestTimeout: 60_000,
    // 10 seconds: ensures efficient resource usage for idle connections
    keepAliveTimeout: 10_000,
    https: await createHttpsOptions(),
    loggerInstance: logger,
    ajv: {
      customOptions: {
        coerceTypes: 'array', // change type of data to match type keyword
        removeAdditional: 'all' // Remove additional body properties
      }
    }
  });

  // 15 seconds: prevents slow clients from holding connections too long
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

  // Apply headersTimeout on the underlying server regardless of HTTP/HTTPS
  app.server.headersTimeout = 15_000;

  // Start server
  const url = new URL(app.config.BASE_URL);

  try {
    await app.listen({
      host: url.hostname,
      port: parseInt(url.port, 10),
      listenTextResolver: (address) => `IT Wallet Credential Issuer listening on ${address}`
    });
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }

  attachServiceIpcAdapter({
    endpoint: app.config.BASE_URL,
    service: 'credential-issuer',
    stop: () => app.close(),
    issuerFaults: {
      activate: async (request) => app.issuerFaultStore.activate(request),
      deactivate: async (request) => app.issuerFaultStore.deactivate(request)
    }
  });

  // Only opens a browser tab when at least one credential identifier is
  // configured (see plugins/config.ts). A browser-launch failure terminates
  // startup, consistent with the app.listen() error handling above.
  if (app.config.CREDENTIAL_OFFER_URI !== undefined) {
    const credentialOfferPageUrl = `${app.config.BASE_URL}/credential-offer`;

    try {
      await open(credentialOfferPageUrl);
    } catch (err) {
      app.log.error(err, `Failed to open the credential offer page in the default browser: ${credentialOfferPageUrl}`);
      process.exit(1);
    }
  }
}

startServer();
