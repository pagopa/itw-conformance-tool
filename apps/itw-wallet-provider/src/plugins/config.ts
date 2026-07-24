import { readFile } from 'node:fs/promises';
import path from 'node:path';

import { loadConfig } from '@itw-conformance-tool/config';
import { convertPemToBase64Der } from '@itw-conformance-tool/crypto';
import { trimTrailingSlashes } from '@itw-conformance-tool/utils';
import fp from 'fastify-plugin';

declare module 'fastify' {
  interface FastifyInstance {
    config: {
      BASE_URL: string;
      DATA_DIR: string;
      TRUST_ANCHOR_URL: string;
      WALLET_NAME: string;
      WALLET_PROVIDER_X509: string;
    };
  }
}

export default fp(
  async function configPlugin(app) {
    const config = loadConfig();
    const walletProviderConfig = config['wallet-provider'];
    const dataDir = config.global.data_dir;
    const certificatePem = await readFile(path.join(dataDir, 'wallet-provider', 'cert.pem'), 'utf8');

    app.decorate('config', {
      BASE_URL: walletProviderConfig.local_url,
      DATA_DIR: dataDir,
      TRUST_ANCHOR_URL: trimTrailingSlashes(config['trust-anchor'].url.trim()),
      WALLET_NAME: config.wallet.wallet_name,
      WALLET_PROVIDER_X509: convertPemToBase64Der(certificatePem)
    });
  },
  { name: 'config' }
);
