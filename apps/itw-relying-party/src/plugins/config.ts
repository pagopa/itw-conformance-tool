import { readFile } from 'node:fs/promises';
import path from 'node:path';

import { loadConfig } from '@itw-conformance-tool/config';
import { convertPemToBase64Der, getLocalRootCaPaths } from '@itw-conformance-tool/crypto';
import fp from 'fastify-plugin';

import type { FastifyPluginAsync } from 'fastify';

declare module 'fastify' {
  interface FastifyInstance {
    config: {
      BASE_URL: string;
      DATA_DIR: string;
      RP_X509: string;
      /** PEM-encoded CA to trust when calling the Trust Anchor over HTTPS. */
      TRUST_ANCHOR_TLS_CA?: string;
      TRUST_ANCHOR_URL: string;
    };
  }
}

/** Reads a PEM file, or `undefined` when it has not been generated. */
async function readFileIfPresent(filePath: string): Promise<string | undefined> {
  try {
    return await readFile(filePath, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    throw error;
  }
}

const configPlugin: FastifyPluginAsync = async (app) => {
  const config = loadConfig();
  const relyingPartyConfig = config['relying-party'];
  const trustAnchorConfig = config['trust-anchor'];

  const dataDir = config.global.data_dir;
  const certificatePem = await readFile(path.join(dataDir, 'rp', 'cert.pem'), 'utf8');

  // Every local service — the Trust Anchor included — serves TLS on a
  // certificate signed by the self-signed root CA `itwct init` writes under
  // `<data_dir>/tls`, which no public trust store knows. Carrying it here is
  // what lets the Relying Party call the Trust Anchor — to assemble the Trust
  // Chain it inlines in a Request Object — with certificate verification on.
  // Only the certificate is read: the CA private key is the tool's, not this
  // service's business. It is missing when the tool runs against a Trust Anchor
  // it did not issue a certificate for, and then the public roots apply.
  const localRootCaCertificatePem = await readFileIfPresent(getLocalRootCaPaths(dataDir).certificatePath);

  app.decorate('config', {
    BASE_URL: relyingPartyConfig.url,
    DATA_DIR: dataDir,
    RP_X509: convertPemToBase64Der(certificatePem),
    TRUST_ANCHOR_TLS_CA: localRootCaCertificatePem,
    TRUST_ANCHOR_URL: trustAnchorConfig.url
  });
};

export default fp(configPlugin, { name: 'config' });
