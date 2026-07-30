import { readFile } from 'node:fs/promises';
import path from 'node:path';

import { loadConfig } from '@itw-conformance-tool/config';
import { convertPemToBase64Der } from '@itw-conformance-tool/crypto';
import fp from 'fastify-plugin';

import type { FastifyPluginAsync } from 'fastify';

declare module 'fastify' {
  interface FastifyInstance {
    config: {
      BASE_URL: string;
      DATA_DIR: string;
      IACA_X509: string;
      TRUST_ANCHOR_URL: string;
    };
  }
}

const configPlugin: FastifyPluginAsync = async (app) => {
  const config = loadConfig();
  const relyingPartyConfig = config['relying-party'];

  const dataDir = config.global.data_dir;
  const certificatePem = await readFile(path.join(dataDir, 'rp', 'cert.pem'), 'utf8');

  app.decorate('config', {
    BASE_URL: relyingPartyConfig.url,
    DATA_DIR: dataDir,
    IACA_X509: convertPemToBase64Der(certificatePem),
    TRUST_ANCHOR_URL: relyingPartyConfig.trust_anchor_url
  });
};

export default fp(configPlugin, { name: 'config' });
