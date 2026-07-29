import { readFile } from 'node:fs/promises';
import path from 'node:path';

import { validateCertificateMatchesJwk } from '@itw-conformance-tool/crypto';
import fp from 'fastify-plugin';
import { calculateJwkThumbprint, type JWK } from 'jose';

import type { Jwk } from '@pagopa/io-wallet-oauth2';
import type { FastifyPluginAsync } from 'fastify';

type JwkUse = 'sig';

interface JwkWithKid extends Jwk {
  kid: string;
  use: JwkUse;
}

type PrivateJwk = JwkWithKid;

interface PublicJwk extends JwkWithKid {
  d?: never;
}

type JwkKeyPair = {
  public: PublicJwk;
  private: PrivateJwk;
};

type JwksByUse = Record<JwkUse, JwkKeyPair>;

declare module 'fastify' {
  interface FastifyInstance {
    jwks: JwksByUse;
  }
}

const parseJwks = (content: string, filePath: string): Jwk[] => {
  const jwks = JSON.parse(content) as unknown;

  if (
    typeof jwks !== 'object' ||
    jwks === null ||
    Array.isArray(jwks) ||
    !('keys' in jwks) ||
    !Array.isArray(jwks.keys)
  ) {
    throw new TypeError(`${filePath} must contain a JWKS with a keys array`);
  }

  return jwks.keys.map((jwk) => {
    if (typeof jwk !== 'object' || jwk === null || Array.isArray(jwk)) {
      throw new TypeError(`${filePath} must contain only JWK objects`);
    }

    return jwk as Jwk;
  });
};

const getKeyPair = async (jwks: Jwk[], selector: { use: JwkUse }, filePath: string): Promise<JwkKeyPair> => {
  const matchingKeys = jwks.filter((jwk) => jwk.use === selector.use);
  const [jwk] = matchingKeys;

  if (matchingKeys.length !== 1) {
    throw new Error(`${filePath} must contain exactly one ${selector.use} JWK`);
  }

  const kid = await calculateJwkThumbprint(jwk as JWK);
  const privateJwk = { ...jwk, kid } as PrivateJwk;
  const { d, key_ops, ...publicKey } = privateJwk;
  void d;
  void key_ops;

  return {
    private: privateJwk,
    public: publicKey
  };
};

const JWK_FILE = 'wallet-provider/jwks.json';

const JWK_SELECTORS = {
  sig: { use: 'sig' }
} as const satisfies Record<keyof JwksByUse, { use: JwkUse }>;

const loadKeyPairs = async (dataDir: string): Promise<JwksByUse> => {
  const filePath = path.join(dataDir, JWK_FILE);
  const content = await readFile(filePath, 'utf8');
  const jwks = parseJwks(content, filePath);

  return {
    sig: await getKeyPair(jwks, JWK_SELECTORS.sig, filePath)
  };
};

async function validateWalletProviderCertificateBinding(dataDir: string, signingPrivateJwk: PrivateJwk): Promise<void> {
  const certificatePath = path.join(dataDir, 'wallet-provider', 'cert.pem');

  try {
    const certificatePem = await readFile(certificatePath, 'utf8');
    await validateCertificateMatchesJwk(certificatePem, signingPrivateJwk as JWK);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(
      `Wallet Provider certificate chain is incompatible with wallet-provider/jwks.json. ` +
        `Run itw-conformance-tool init --force to regenerate a coherent certificate chain. ${message}`
    );
  }
}

const jwkPlugin: FastifyPluginAsync = async (app) => {
  const dataDir = app.config.DATA_DIR;

  const jwks = await loadKeyPairs(dataDir);
  await validateWalletProviderCertificateBinding(dataDir, jwks.sig.private);

  app.decorate('jwks', jwks);
};

export default fp(jwkPlugin, {
  name: 'jwk-plugin',
  dependencies: ['config']
});
