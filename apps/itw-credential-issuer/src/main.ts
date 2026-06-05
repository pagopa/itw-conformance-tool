import { readFileSync } from 'node:fs';

import { logger } from '@itw-conformance-tool/logger';
import closeWithGrace from 'close-with-grace';
import Fastify from 'fastify';
import fp from 'fastify-plugin';

import bootstrap from './app.js';

function resolveTlsOptions(): { cert: Buffer; key: Buffer } | undefined {
  const httpsEnabled = process.env['ITW_CT_HTTPS'] ?? process.env['HTTPS_ENABLED'];
  if (!httpsEnabled || httpsEnabled === 'false' || httpsEnabled === '0') {
    return undefined;
  }

  const certPath = process.env['ITW_CT_TLS_CERT_PATH'] ?? process.env['TLS_CERT_PATH'] ?? '';
  const keyPath = process.env['ITW_CT_TLS_KEY_PATH'] ?? process.env['TLS_KEY_PATH'] ?? '';

  if (!certPath || !keyPath) {
    throw new Error('HTTPS_ENABLED is true but TLS_CERT_PATH or TLS_KEY_PATH is missing');
  }

  return { cert: readFileSync(certPath), key: readFileSync(keyPath) };
}

async function startServer() {
  const tls = resolveTlsOptions();

  const app = Fastify({
    loggerInstance: logger,
    ...(tls ? { https: tls } : {}),
    // Apply recommended timeouts to prevent slow or idle clients from holding connections open
    connectionTimeout: 120_000,
    requestTimeout: 60_000,
    keepAliveTimeout: 10_000,
    ...(tls ? {} : { http: { headersTimeout: 15_000 } }),
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
    await app.close();
  });

  await app.ready();

  // Start server
  try {
    await app.listen({
      host: app.config.HOST,
      port: app.config.PORT,
      listenTextResolver: (address) =>
        `IT Wallet Credential Issuer listening on ${tls ? address.replace('http://', 'https://') : address}`
    });
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
}

startServer();
