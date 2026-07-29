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
      WALLET_PROVIDER_X509_CHAIN: [string, string];
    };
  }
}

async function readWalletProviderCertificate(filePath: string): Promise<string> {
  try {
    return await readFile(filePath, 'utf8');
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(
      `Wallet Provider cryptographic material is missing or unreadable at '${filePath}'. ` +
        `Run itw-conformance-tool init --force to regenerate a coherent certificate chain. ${message}`
    );
  }
}

export default fp(
  async function configPlugin(app) {
    const config = loadConfig();
    const walletProviderConfig = config['wallet-provider'];
    const dataDir = config.global.data_dir;
    const certificatePem = await readWalletProviderCertificate(path.join(dataDir, 'wallet-provider', 'cert.pem'));
    const intermediateCertificatePem = await readWalletProviderCertificate(
      path.join(dataDir, 'wallet-provider', 'intermediate-cert.pem')
    );

    app.decorate('config', {
      BASE_URL: walletProviderConfig.local_url,
      DATA_DIR: dataDir,
      TRUST_ANCHOR_URL: trimTrailingSlashes(config['trust-anchor'].url.trim()),
      WALLET_NAME: config.wallet.wallet_name,
      WALLET_PROVIDER_X509_CHAIN: [
        convertPemToBase64Der(certificatePem),
        convertPemToBase64Der(intermediateCertificatePem)
      ]
    });
  },
  { name: 'config' }
);
