import { readFile } from 'node:fs/promises';
import path from 'node:path';

import { loadTrustAnchorFederationJwk } from '@itw-conformance-tool/crypto';
import fp from 'fastify-plugin';

import type { TrustAnchorFederationJwk } from '@itw-conformance-tool/crypto';
import type { Jwk } from '@pagopa/io-wallet-oauth2';
import type { FastifyPluginAsync } from 'fastify';

type JwkUse = 'enc' | 'sig';

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

type JwksByUse = Record<JwkUse, JwkKeyPair> & {
  federation: JwkKeyPair;
};

declare module 'fastify' {
  interface FastifyInstance {
    jwks: JwksByUse;
    /** The Trust Anchor's federation private key, read from the shared `data_dir`.
     * The Relying Party signs no federation artifact with it except the Trust Anchor-issued
     * Trust Mark it embeds in its own Entity Configuration. */
    trustAnchorFederationJwk: TrustAnchorFederationJwk;
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

const getKeyPair = (jwks: Jwk[], selector: { kid: string; use: JwkUse }, filePath: string): JwkKeyPair => {
  const matchingKeys = jwks.filter((jwk) => jwk.kid === selector.kid);
  const [jwk] = matchingKeys;

  if (matchingKeys.length !== 1 || jwk.use !== selector.use) {
    throw new Error(`${filePath} must contain exactly one ${selector.use} JWK with kid ${selector.kid}`);
  }

  const privateJwk = jwk as PrivateJwk;
  const { d, key_ops, ...publicKey } = privateJwk;
  void d;
  void key_ops;

  return {
    private: privateJwk,
    public: publicKey
  };
};

const JWK_FILE = 'rp/jwks.json';

const JWK_SELECTORS = {
  enc: { kid: 'rp-encryption-key', use: 'enc' },
  federation: { kid: 'rp-federation-key', use: 'sig' },
  sig: { kid: 'rp-signing-key', use: 'sig' }
} as const satisfies Record<keyof JwksByUse, { kid: string; use: JwkUse }>;

const loadKeyPairs = async (dataDir: string): Promise<JwksByUse> => {
  const filePath = path.join(dataDir, JWK_FILE);
  const content = await readFile(filePath, 'utf8');
  const jwks = parseJwks(content, filePath);

  return {
    enc: getKeyPair(jwks, JWK_SELECTORS.enc, filePath),
    federation: getKeyPair(jwks, JWK_SELECTORS.federation, filePath),
    sig: getKeyPair(jwks, JWK_SELECTORS.sig, filePath)
  };
};

const jwkPlugin: FastifyPluginAsync = async (app) => {
  const dataDir = app.config.DATA_DIR;

  const [jwks, trustAnchorFederationJwk] = await Promise.all([
    loadKeyPairs(dataDir),
    loadTrustAnchorFederationJwk(dataDir)
  ]);

  app.decorate('jwks', jwks);
  app.decorate('trustAnchorFederationJwk', trustAnchorFederationJwk);
};

export default fp(jwkPlugin, {
  name: 'jwk-plugin',
  dependencies: ['config']
});
