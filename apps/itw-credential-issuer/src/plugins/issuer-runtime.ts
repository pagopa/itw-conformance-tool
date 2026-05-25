import {
  callbacks,
  getEncryptJweCallback,
  getSignJwtCallback,
  getSdkConfig,
  resolveSpecVersionFromHeaders,
  toPublicJwk
} from '@itw-conformance-tool/issuer';

import type { ICodeJwtParRepository, ITokenParRepository, JwksRepository } from '@itw-conformance-tool/issuer';
import type { CallbackContext } from '@pagopa/io-wallet-oauth2';
import type { IoWalletSdkConfig } from '@pagopa/io-wallet-utils';
import type { FastifyInstance, FastifyRequest } from 'fastify';

function toHeaders(request: FastifyRequest): Headers {
  const entries = Object.entries(request.headers)
    .filter((entry) => typeof entry[1] === 'string')
    .map(([name, value]) => [name, value as string]);

  return new Headers(entries as Array<[string, string]>);
}

function getBaseURL(app: FastifyInstance): string {
  return `${app.config.BASE_URL_SCHEME}://${app.config.HOST}:${app.config.PORT}`;
}

interface RuntimeConfig {
  headers: Headers;
  sdkConfig: IoWalletSdkConfig;
}

function getRuntimeConfig(request: FastifyRequest): RuntimeConfig {
  const headers = toHeaders(request);
  const specVersion = resolveSpecVersionFromHeaders(headers);

  return {
    headers,
    sdkConfig: getSdkConfig(specVersion)
  };
}

interface JwkKey {
  d?: string;
  kid?: string;
  alg?: string;
  [key: string]: unknown;
}

interface KeyPair {
  private: JwkKey & { d: string; kid: string; kty: 'EC'; alg: string };
  public: unknown;
}

function keyPairFromKey(key: JwkKey): KeyPair {
  if (!key?.d) {
    throw new Error('Expected a private EC key with d parameter in issuer JWKS');
  }
  if (!key?.kid) {
    throw new Error('Expected kid for issuer JWKS key');
  }

  const privateKey = {
    ...key,
    d: key.d,
    kid: key.kid,
    kty: 'EC' as const,
    alg: key.alg ?? 'ES256'
  };

  return {
    private: privateKey,
    public: toPublicJwk(privateKey)
  };
}

export function makeJwksRepository(app: FastifyInstance): JwksRepository {
  const keys = app.issuerKeys.signingKeysJwks.keys;
  if (!Array.isArray(keys) || keys.length === 0) {
    throw new Error('Issuer JWKS does not contain keys');
  }

  const signKey = keyPairFromKey(keys[0] as JwkKey);
  const encryptKey = keyPairFromKey((keys[1] ?? keys[0]) as JwkKey);

  return {
    getEncrypt: () => encryptKey as unknown as ReturnType<JwksRepository['getEncrypt']>,
    getSign: () => signKey as unknown as ReturnType<JwksRepository['getSign']>,
    iacaX509: () => app.issuerKeys.iacaCertPem
  };
}

interface OAuthCallbacksResult {
  baseURL: string;
  headers: Headers;
  jwksRepository: JwksRepository;
  oauthCallbacks: Pick<CallbackContext, 'encryptJwe' | 'fetch' | 'generateRandom' | 'hash' | 'signJwt' | 'verifyJwt'>;
  sdkConfig: IoWalletSdkConfig;
}

export function makeOauthCallbacks(app: FastifyInstance, request: FastifyRequest): OAuthCallbacksResult {
  const { headers, sdkConfig } = getRuntimeConfig(request);
  const jwksRepository = makeJwksRepository(app);

  const { public: encryptPublic } = jwksRepository.getEncrypt();
  const { private: signPrivate } = jwksRepository.getSign();

  return {
    headers,
    sdkConfig,
    jwksRepository,
    oauthCallbacks: {
      ...callbacks,
      encryptJwe: getEncryptJweCallback(encryptPublic),
      signJwt: getSignJwtCallback([signPrivate]),
      fetch: fetch.bind(globalThis)
    },
    baseURL: getBaseURL(app)
  };
}

export function makeTokenParRepository(app: FastifyInstance): ITokenParRepository {
  return {
    consume: async (requestUri: string) => {
      await app.parRepository.delete(requestUri);
    },
    // Async wrapper around a synchronous SQLite query to match the repository interface.
    // node:sqlite uses DatabaseSync intentionally; the async signature allows future DB abstraction.
    getByCode: async (code: string) => {
      const row = app.dbClient.db
        .prepare(
          `SELECT request_uri, request_object
           FROM par_entries
           WHERE json_extract(request_object, '$.code') = ?
             AND json_extract(request_object, '$.code_expires_at') >= unixepoch('now')
             AND expires_at >= unixepoch('now') * 1000`
        )
        .get(code);

      if (!row) {
        return undefined;
      }

      return {
        requestUri: row.request_uri as string,
        parRequest: JSON.parse(row.request_object as string)
      };
    }
  };
}

export function makeCodeJwtParRepository(app: FastifyInstance): ICodeJwtParRepository {
  return {
    get: async (requestUri: string) => {
      const entry = await app.parRepository.get(requestUri);
      if (!entry) {
        return undefined;
      }

      const parRequest = JSON.parse(entry.requestObject);

      return {
        clientId: parRequest.client_id,
        redirectUri: parRequest.redirect_uri,
        requestUri,
        state: parRequest.state
      };
    },
    setCode: async (requestUri: string, code: string, codeExpiresAt: number) => {
      const entry = await app.parRepository.get(requestUri);
      if (!entry) {
        return;
      }

      const parRequest = JSON.parse(entry.requestObject);
      const updated = {
        ...parRequest,
        code,
        code_expires_at: codeExpiresAt
      };

      await app.parRepository.update(requestUri, {
        requestObject: JSON.stringify(updated)
      });
    }
  };
}
