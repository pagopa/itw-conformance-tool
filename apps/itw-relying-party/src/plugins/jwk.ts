import { readFile } from 'node:fs/promises';
import path from 'node:path';

import fp from 'fastify-plugin';

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
  }
}

const parseJwk = (content: string, filePath: string): Jwk => {
  const jwk = JSON.parse(content) as unknown;

  if (typeof jwk !== 'object' || jwk === null || Array.isArray(jwk)) {
    throw new TypeError(`${filePath} must contain a single private JWK object`);
  }

  return jwk as Jwk;
};

const getKeyPair = (jwk: Jwk, use: JwkUse, filePath: string): JwkKeyPair => {
  if (jwk.use !== use || typeof jwk.kid !== 'string') {
    throw new Error(`${filePath} must contain a ${use} JWK with a kid`);
  }

  const privateJwk = jwk as PrivateJwk;
  const { d, ...publicKey } = privateJwk;
  void d;

  return {
    private: privateJwk,
    public: publicKey
  };
};

const JWK_FILES = {
  enc: { file: 'rp/auth-response-key.jwk.json', use: 'enc' },
  federation: { file: 'rp/federation-key.jwk.json', use: 'sig' },
  sig: { file: 'rp/auth-request-key.jwk.json', use: 'sig' }
} as const satisfies Record<keyof JwksByUse, { file: string; use: JwkUse }>;

const loadKeyPair = async (dataDir: string, file: string, use: JwkUse): Promise<JwkKeyPair> => {
  const filePath = path.join(dataDir, file);
  const content = await readFile(filePath, 'utf8');
  const jwk = parseJwk(content, filePath);

  return getKeyPair(jwk, use, filePath);
};

const jwkPlugin: FastifyPluginAsync = async (app) => {
  const [enc, federation, sig] = await Promise.all([
    loadKeyPair(app.config.DATA_DIR, JWK_FILES.enc.file, JWK_FILES.enc.use),
    loadKeyPair(app.config.DATA_DIR, JWK_FILES.federation.file, JWK_FILES.federation.use),
    loadKeyPair(app.config.DATA_DIR, JWK_FILES.sig.file, JWK_FILES.sig.use)
  ]);

  app.decorate('jwks', {
    enc,
    federation,
    sig
  });
};

export default fp(jwkPlugin, {
  name: 'jwk-plugin',
  dependencies: ['config']
});
