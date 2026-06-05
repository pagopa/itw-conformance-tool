import { readFileSync } from 'node:fs';

import { logger } from '@itw-conformance-tool/logger';
import closeWithGrace from 'close-with-grace';
import Fastify from 'fastify';
import fp from 'fastify-plugin';

import bootstrap from './app.js';

function resolveTlsOptions(): { cert: Buffer; key: Buffer } | undefined {
  const httpsEnabledRaw = (process.env['ITW_CT_HTTPS'] ?? process.env['HTTPS_ENABLED'])?.trim().toLowerCase();
  if (httpsEnabledRaw !== 'true' && httpsEnabledRaw !== '1') {
    return undefined;
  }

  const certPath = (process.env['ITW_CT_TLS_CERT_PATH'] ?? '').trim();
  const keyPath = (process.env['ITW_CT_TLS_KEY_PATH'] ?? '').trim();

  if (!certPath || !keyPath) {
    throw new Error('HTTPS is enabled but ITW_CT_TLS_CERT_PATH or ITW_CT_TLS_KEY_PATH is missing');
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
        coerceTypes: 'array',
        removeAdditional: 'all'
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

  // Apply headersTimeout on the underlying server regardless of HTTP/HTTPS
  app.server.headersTimeout = 15_000;

  try {
    await app.listen({
      host: app.config.host,
      port: app.config.port,
      listenTextResolver: (address) =>
        `IT Wallet Relying Party listening on ${tls ? address.replace('http://', 'https://') : address} (base URL: ${app.config.baseUrl})`
    });
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
}

startServer();
