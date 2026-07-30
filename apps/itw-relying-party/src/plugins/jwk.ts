import { readFile } from 'node:fs/promises';
import path from 'node:path';

import fp from 'fastify-plugin';
import { calculateJwkThumbprint, type JWK } from 'jose';

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

const getKeyPair = async (jwk: Jwk | undefined, filePath: string, description: string): Promise<JwkKeyPair> => {
  if (!jwk) {
    throw new Error(`${filePath} must contain ${description}`);
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

const selectEncryptionJwk = (jwks: Jwk[]): Jwk | undefined =>
  jwks.find((jwk) => jwk.kty === 'EC' && jwk.alg === 'ECDH-ES' && jwk.use === 'enc' && typeof jwk.d === 'string');

const selectSigningJwk = (jwks: Jwk[], index: number): Jwk | undefined => {
  const signingJwks = jwks.filter(
    (jwk) => jwk.kty === 'EC' && jwk.alg === 'ES256' && jwk.use === 'sig' && typeof jwk.d === 'string'
  );
  return signingJwks[index];
};

const JWK_FILE = 'rp/jwks.json';

const loadKeyPairs = async (dataDir: string): Promise<JwksByUse> => {
  const filePath = path.join(dataDir, JWK_FILE);
  const content = await readFile(filePath, 'utf8');
  const jwks = parseJwks(content, filePath);

  return {
    enc: await getKeyPair(selectEncryptionJwk(jwks), filePath, 'one private ECDH-ES encryption JWK'),
    federation: await getKeyPair(selectSigningJwk(jwks, 1), filePath, 'a second private ES256 signing JWK'),
    sig: await getKeyPair(selectSigningJwk(jwks, 0), filePath, 'a first private ES256 signing JWK')
  };
};

const jwkPlugin: FastifyPluginAsync = async (app) => {
  const dataDir = app.config.DATA_DIR;

  const jwks = await loadKeyPairs(dataDir);

  app.decorate('jwks', jwks);
};

export default fp(jwkPlugin, {
  name: 'jwk-plugin',
  dependencies: ['config']
});
