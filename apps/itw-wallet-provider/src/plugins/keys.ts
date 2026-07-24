import { readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';

import { isValidJwk, validateJWKS } from '@itw-conformance-tool/crypto';
import fp from 'fastify-plugin';

import type { JsonWebKey } from '@pagopa/io-wallet-oid-federation';
import type { JWK } from 'jose';

export type WalletProviderSigningJwk = JsonWebKey & {
  d: string;
  kid: string;
  kty: string;
  x: string;
  y: string;
  crv: string;
};

export type WalletProviderPublicJwk = JsonWebKey & {
  kid: string;
  kty: string;
};

export type WalletProviderKeys = {
  signingPrivateJwk: WalletProviderSigningJwk;
  signingPublicJwk: WalletProviderPublicJwk;
};

declare module 'fastify' {
  interface FastifyInstance {
    walletProviderKeys: WalletProviderKeys;
  }
}

function isCompatibleSigningKey(key: unknown): key is WalletProviderSigningJwk {
  return (
    !!key &&
    typeof key === 'object' &&
    !Array.isArray(key) &&
    (key as JWK).kty === 'EC' &&
    (key as JWK).crv === 'P-256' &&
    typeof (key as JWK).d === 'string' &&
    typeof (key as JWK).kid === 'string' &&
    typeof (key as JWK).x === 'string' &&
    typeof (key as JWK).y === 'string' &&
    (key as JWK).alg === 'ES256' &&
    (key as JWK).use === 'sig' &&
    Array.isArray((key as JWK).key_ops) &&
    (key as JWK).key_ops?.includes('sign') === true
  );
}

async function loadSigningKeys(dataDir: string): Promise<WalletProviderKeys> {
  const relativeFile = join('wallet-provider', 'jwks.json');
  const keyPath = resolve(dataDir, relativeFile);

  try {
    const content = await readFile(keyPath, 'utf8');
    const jwks = JSON.parse(content) as unknown;
    await validateJWKS(jwks);

    if (!jwks || typeof jwks !== 'object' || Array.isArray(jwks) || !('keys' in jwks) || !Array.isArray(jwks.keys)) {
      throw new Error('JWKS does not contain a keys array');
    }

    const signingPrivateJwk = jwks.keys.find(isCompatibleSigningKey);
    if (!signingPrivateJwk) {
      throw new Error('JWKS does not contain an EC P-256 ES256 signing key');
    }
    if (!(await isValidJwk(signingPrivateJwk))) {
      throw new Error('signing JWK failed cryptographic validation');
    }

    const { d, key_ops, ...signingPublicJwk } = signingPrivateJwk;
    void d;
    void key_ops;
    return { signingPrivateJwk, signingPublicJwk: signingPublicJwk as WalletProviderPublicJwk };
  } catch (error) {
    throw new Error(
      `Invalid Wallet Provider key file ${relativeFile}: ${error instanceof Error ? error.message : String(error)}. ` +
        'Run itwct init --force to generate valid Wallet Provider signing keys.'
    );
  }
}

export default fp(
  async function keysPlugin(app) {
    app.decorate('walletProviderKeys', await loadSigningKeys(app.config.dataDir));
  },
  { name: 'keys', dependencies: ['config'] }
);
