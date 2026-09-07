import { readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';

import { convertPemToBase64Der, isValidJwk, validateJWKS } from '@itw-conformance-tool/crypto';
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
  /**
   * The Trust Anchor federation certificate, DER-encoded, as a single-element
   * `x5c` chain. It is self-signed and is the root every other service's `x5c`
   * chain terminates at, so publishing it in the Trust Anchor's own Entity
   * Configuration is what lets a verifier obtain that root from the federation
   * rather than having to be provisioned with it out of band.
   */
  federationCertificateChain: string[];
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

  throw new Error('JWKS does not contain an EC signing key compatible with ES algorithms');
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
 *
 * Used for the issuer and the Wallet Provider, which sign their Entity
 * Configuration with the same key their runtime signs everything else with. The
 * Relying Party does not: its federation key is a distinct key in a file of its
 * own, read through `loadFederationJwk`.
 */
async function loadFederationJwkFromJwks(dataDir: string, relativeFile: string): Promise<JwkKey> {
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

    return pickSigningKey(parsedJwks.keys);
  } catch (err) {
    throw new Error(
      `Invalid key format in ${relativeFile}: ${err instanceof Error ? err.message : String(err)}. ` +
        `Please ensure the file contains a valid JWKS with an EC signing key.`
    );
  }
}

/** Reads the Trust Anchor federation certificate, which certifies the key the
 * Trust Anchor signs every federation statement with.
 */
async function loadFederationCertificate(dataDir: string): Promise<string> {
  const certificatePath = resolve(dataDir, join('trust-anchor', 'federation-cert.pem'));

  try {
    return await readFile(certificatePath, 'utf8');
  } catch {
    throw new Error(
      `Missing required key material: trust-anchor/federation-cert.pem not found in ${dataDir}. ` +
        `Please ensure the certificate exists before starting the server (run the CLI's init command).`
    );
  }
}

export default fp(
  async function keysPlugin(app) {
    const { dataDir } = app.config;

    const [
      federationCertificatePem,
      federationPrivateJwk,
      issuerFederationJwk,
      rpFederationJwk,
      walletProviderFederationJwk
    ] = await Promise.all([
      loadFederationCertificate(dataDir),
      loadFederationJwk(dataDir, join('trust-anchor', 'federation-key.jwk.json')),
      loadFederationJwkFromJwks(dataDir, join('issuer', 'jwks.json')),
      // The subordinate statement must carry the key the Relying Party
      // actually signs its Entity Configuration with — its federation key,
      // which lives in its own file rather than as the second `use=sig` entry
      // of `rp/jwks.json`.
      loadFederationJwk(dataDir, join('rp', 'federation-key.jwk.json')),
      loadFederationJwkFromJwks(dataDir, join('wallet-provider', 'jwks.json'))
    ]);

    app.decorate('trustAnchorKeys', {
      federationCertificateChain: [convertPemToBase64Der(federationCertificatePem)],
      federationPrivateJwk,
      issuerFederationJwk,
      rpFederationJwk,
      walletProviderFederationJwk
    });
  },
  { name: 'keys', dependencies: ['config'] }
);
