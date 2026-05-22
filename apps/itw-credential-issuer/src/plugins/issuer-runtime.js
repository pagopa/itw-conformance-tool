import {
  callbacks,
  getEncryptJweCallback,
  getSignJwtCallback,
  getSdkConfig,
  resolveSpecVersionFromHeaders,
  toPublicJwk
} from '@itw-conformance-tool/issuer';

function toHeaders(request) {
  const entries = Object.entries(request.headers)
    .filter((entry) => typeof entry[1] === 'string')
    .map(([name, value]) => [name, value]);

  return new Headers(entries);
}

function getBaseURL(app) {
  return `http://${app.config.HOST}:${app.config.PORT}`;
}

function getRuntimeConfig(request) {
  const headers = toHeaders(request);
  const specVersion = resolveSpecVersionFromHeaders(headers);

  return {
    headers,
    sdkConfig: getSdkConfig(specVersion)
  };
}

function keyPairFromKey(key) {
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
    kty: 'EC',
    alg: key.alg ?? 'ES256'
  };

  return {
    private: privateKey,
    public: toPublicJwk(privateKey)
  };
}

export function makeJwksRepository(app) {
  const keys = app.issuerKeys.signingKeysJwks.keys;
  if (!Array.isArray(keys) || keys.length === 0) {
    throw new Error('Issuer JWKS does not contain keys');
  }

  const signKey = keyPairFromKey(keys[0]);
  const encryptKey = keyPairFromKey(keys[1] ?? keys[0]);

  return {
    getEncrypt: () => encryptKey,
    getSign: () => signKey,
    iacaX509: () => app.issuerKeys.iacaCertPem
  };
}

export function makeOauthCallbacks(app, request) {
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

export function makeTokenParRepository(app) {
  return {
    consume: async (requestUri) => {
      await app.parRepository.delete(requestUri);
    },
    // Async wrapper around a synchronous SQLite query to match the repository interface.
    // node:sqlite uses DatabaseSync intentionally; the async signature allows future DB abstraction.
    getByCode: async (code) => {
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
        requestUri: row.request_uri,
        parRequest: JSON.parse(row.request_object)
      };
    }
  };
}

export function makeCodeJwtParRepository(app) {
  return {
    get: async (requestUri) => {
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
    setCode: async (requestUri, code, codeExpiresAt) => {
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
