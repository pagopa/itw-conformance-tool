import { readFileSync } from 'node:fs';
import path from 'node:path';

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

  const dataDir = (process.env['ITW_CT_DATA_DIR'] ?? process.env['DATA_DIR'] ?? '').trim();
  const defaultCertPath = dataDir.length > 0 ? path.join(dataDir, 'tls_cert.pem') : '';
  const defaultKeyPath = dataDir.length > 0 ? path.join(dataDir, 'tls_key.pem') : '';

  const certPath = (process.env['ITW_CT_TLS_CERT_PATH'] ?? process.env['TLS_CERT_PATH'] ?? defaultCertPath).trim();
  const keyPath = (process.env['ITW_CT_TLS_KEY_PATH'] ?? process.env['TLS_KEY_PATH'] ?? defaultKeyPath).trim();

  if (!certPath || !keyPath) {
    throw new Error(
      'HTTPS is enabled but no TLS cert/key could be resolved. Provide TLS_CERT_PATH/TLS_KEY_PATH (or ITW_CT_TLS_CERT_PATH/ITW_CT_TLS_KEY_PATH), or ensure DATA_DIR contains tls_cert.pem and tls_key.pem.'
    );
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

  // Apply headersTimeout on the underlying server regardless of HTTP/HTTPS
  app.server.headersTimeout = 15_000;

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
