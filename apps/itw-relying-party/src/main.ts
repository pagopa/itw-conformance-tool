import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

import { logger } from '@itw-conformance-tool/logger';
import { loadRpConfig } from '@itw-conformance-tool/rp';
import closeWithGrace from 'close-with-grace';
import Fastify from 'fastify';
import fp from 'fastify-plugin';

import bootstrap from './app.js';

function readTlsFileWithFallback(primaryPath: string, legacyFileName: string): Buffer {
  if (existsSync(primaryPath)) {
    return readFileSync(primaryPath);
  }

  const legacyPath = join(dirname(primaryPath), legacyFileName);
  if (existsSync(legacyPath)) {
    logger.warn({ legacyPath, primaryPath }, 'Using legacy TLS file path; regenerate with CLI init to migrate names');
    return readFileSync(legacyPath);
  }

  throw new Error(
    `TLS file not found: ${primaryPath} (also checked legacy path: ${legacyPath}). Run "pnpm nx run itw-conformance-cli:build:production && node apps/cli/dist/main.js init --force" to regenerate local TLS assets.`
  );
}

function resolveTlsOptions(): { cert: Buffer; key: Buffer } | undefined {
  const configFilePath = resolve(process.cwd(), process.env['ITW_CT_CONFIG_FILE'] ?? 'config.ini');
  const { config } = loadRpConfig({ configFilePath });

  if (!config.httpsEnabled) {
    return undefined;
  }

  return {
    cert: readTlsFileWithFallback(config.tlsCertPath, 'tls_cert.pem'),
    key: readTlsFileWithFallback(config.tlsKeyPath, 'tls_key.pem')
  };
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
