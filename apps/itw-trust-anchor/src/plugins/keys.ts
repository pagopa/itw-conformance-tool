import { readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';

import { isValidJwk, TRUST_ANCHOR_FEDERATION_KEY_FILE, validateJWKS } from '@itw-conformance-tool/crypto';
import fp from 'fastify-plugin';

export interface JwkKey {
  kty?: string;
  d?: string;
  kid?: string;
  alg?: string;
  use?: string;
  crv?: string;
  x?: string;
  y?: string;
  [key: string]: unknown;
}

export type TrustAnchorKeys = {
  federationPrivateJwk: JwkKey;
  issuerFederationJwk: JwkKey;
  rpFederationJwk: JwkKey;
  walletProviderFederationJwk: JwkKey;
};

declare module 'fastify' {
  interface FastifyInstance {
    trustAnchorKeys: TrustAnchorKeys;
  }
}

function isEcPrivateJwk(jwk: unknown): jwk is JwkKey {
  if (
    !jwk ||
    typeof jwk !== 'object' ||
    Array.isArray(jwk) ||
    !('kty' in jwk) ||
    !('d' in jwk) ||
    !('crv' in jwk) ||
    !('x' in jwk) ||
    !('y' in jwk)
  ) {
    return false;
  }

  return (
    jwk.kty === 'EC' &&
    typeof jwk.d === 'string' &&
    typeof jwk.crv === 'string' &&
    typeof jwk.x === 'string' &&
    typeof jwk.y === 'string'
  );
}

// Mirrors the issuer runtime's own signing-key selection
// (apps/itw-credential-issuer/src/plugins/issuer-runtime.ts) so the Trust Anchor
// resolves the exact same key the issuer advertises in its own federation entity
// configuration.
function pickSigningKey(keys: JwkKey[]): JwkKey {
  const preferred = keys.find(
    (key) => isEcPrivateJwk(key) && key.use === 'sig' && (key.alg === undefined || key.alg.startsWith('ES'))
  );
  if (preferred) {
    return preferred;
  }

  const fallback = keys.find((key) => isEcPrivateJwk(key) && (key.alg === undefined || key.alg.startsWith('ES')));
  if (fallback) {
    return fallback;
  }

  throw new Error('Issuer JWKS does not contain an EC signing key compatible with ES algorithms');
}

function parseJwkFileContent(content: string): unknown {
  const firstPass = JSON.parse(content) as unknown;
  return typeof firstPass === 'string' ? (JSON.parse(firstPass) as unknown) : firstPass;
}

function hasJwkKeys(value: unknown): value is { keys: JwkKey[] } {
  return (
    !!value &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    'keys' in value &&
    Array.isArray(value.keys) &&
    value.keys.every((key) => !!key && typeof key === 'object' && !Array.isArray(key))
  );
}

/** Reads and validates a single private-key JWK file (e.g. a federation signing key).
 * Fails fast with a precise error instead of generating replacement key material.
 */
async function loadFederationJwk(dataDir: string, relativeFile: string): Promise<JwkKey> {
  const keyPath = resolve(dataDir, relativeFile);
  let content: string;

  try {
    content = await readFile(keyPath, 'utf8');
  } catch {
    throw new Error(
      `Missing required key: ${relativeFile} not found in ${dataDir}. ` +
        `Please ensure the key file exists before starting the server (run the CLI's init command).`
    );
  }

  try {
    const jwk = parseJwkFileContent(content);

    if (!jwk || typeof jwk !== 'object' || Array.isArray(jwk) || !isEcPrivateJwk(jwk as JwkKey)) {
      throw new Error('expected an EC private JWK (kty=EC with d/crv/x/y)');
    }

    if (!(await isValidJwk(jwk))) {
      throw new Error('JWK failed cryptographic validation');
    }

    return jwk as JwkKey;
  } catch (err) {
    throw new Error(
      `Invalid key format in ${relativeFile}: ${err instanceof Error ? err.message : String(err)}. ` +
        `Please ensure the key file contains a valid JWK.`
    );
  }
}

/** Reads a service JWKS file and selects the federation-capable signing key.
 * The RP keeps this key in `rp/jwks.json`, alongside its authorization-request
 * signing and encryption keys.
 */
async function loadFederationJwkFromJwks(
  dataDir: string,
  relativeFile: string,
  federationKeyId?: string
): Promise<JwkKey> {
  const jwksPath = resolve(dataDir, relativeFile);
  let content: string;

  try {
    content = await readFile(jwksPath, 'utf8');
  } catch {
    throw new Error(
      `Missing required key: ${relativeFile} not found in ${dataDir}. ` +
        `Please ensure the key material exists before starting the server (run the CLI's init command).`
    );
  }

  try {
    const parsedJwks = JSON.parse(content) as unknown;
    await validateJWKS(parsedJwks);
    if (!hasJwkKeys(parsedJwks) || parsedJwks.keys.length === 0) {
      throw new Error('JWKS does not contain any keys');
    }

    if (federationKeyId) {
      const federationKey = parsedJwks.keys.find(
        (key) => key.kid === federationKeyId && key.use === 'sig' && isEcPrivateJwk(key)
      );
      if (!federationKey) {
        throw new Error(`JWKS does not contain the federation signing key ${federationKeyId}`);
      }
      return federationKey;
    }

    return pickSigningKey(parsedJwks.keys);
  } catch (err) {
    throw new Error(
      `Invalid key format in ${relativeFile}: ${err instanceof Error ? err.message : String(err)}. ` +
        `Please ensure the file contains a valid JWKS with an EC signing key.`
    );
  }
}

export default fp(
  async function keysPlugin(app) {
    const { dataDir } = app.config;

    const [federationPrivateJwk, issuerFederationJwk, rpFederationJwk, walletProviderFederationJwk] = await Promise.all(
      [
        loadFederationJwk(dataDir, TRUST_ANCHOR_FEDERATION_KEY_FILE),
        loadFederationJwkFromJwks(dataDir, join('issuer', 'jwks.json')),
        loadFederationJwkFromJwks(dataDir, join('rp', 'jwks.json'), 'rp-federation-key'),
        loadFederationJwkFromJwks(dataDir, join('wallet-provider', 'jwks.json'), 'wallet-provider-signing-key')
      ]
    );

    app.decorate('trustAnchorKeys', {
      federationPrivateJwk,
      issuerFederationJwk,
      rpFederationJwk,
      walletProviderFederationJwk
    });
  },
  { name: 'keys', dependencies: ['config'] }
);
