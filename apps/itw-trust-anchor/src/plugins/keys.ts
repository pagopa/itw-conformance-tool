import { readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';

import {
  convertPemToBase64Der,
  isValidJwk,
  validateCertificateMatchesJwk,
  validateJWKS
} from '@itw-conformance-tool/crypto';
import fp from 'fastify-plugin';

import { stripPrivateParams, toThumbprintPublicJwk, withCertificateChain } from '../federation/public-jwk.js';

import type { JsonWebKey } from '@pagopa/io-wallet-oid-federation';
import type { JWK } from 'jose';

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
   *
   * Unlike the subordinate keys below, this chain is kept apart from the key it
   * certifies: the `entity-configuration-nonmatching-signing-key` fault
   * publishes a different key in its place and must publish it with no
   * certificate at all, so the two have to stay detachable.
   */
  federationCertificateChain: string[];
  federationPrivateJwk: JwkKey;
  /**
   * Each subordinate's federation key exactly as a subordinate statement
   * publishes it: private material stripped, `kid` resolved the way the subject
   * itself advertises it, and the certifying chain already attached as `x5c`.
   *
   * The certificate is fused onto the key here, at load time, rather than
   * carried alongside it for a publication site to combine — the same shape the
   * Relying Party's `jwk` plugin and the Credential Issuer's `JwksRepository`
   * use. A key and a chain travelling as separate values are paired by
   * convention at every site that publishes them, and that is how a certificate
   * ends up published beside a key it does not certify.
   *
   * Only the public half is kept. The Trust Anchor signs every statement with
   * its own federation key and never with a subordinate's, so it has no use for
   * their private material.
   */
  subordinatePublicJwks: Record<SubordinateName, JsonWebKey>;
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

/** Reads a PEM certificate, naming the artifact and how to regenerate it. */
async function loadCertificate(dataDir: string, relativeFile: string): Promise<string> {
  const certificatePath = resolve(dataDir, relativeFile);

  try {
    return await readFile(certificatePath, 'utf8');
  } catch {
    throw new Error(
      `Missing required key material: ${relativeFile} not found in ${dataDir}. ` +
        `Please ensure the certificate exists before starting the server (run the CLI's init command).`
    );
  }
}

/** How a subordinate's federation key and its certificate chain are found on disk,
 * and how the subordinate itself identifies that key. */
type SubordinateKeySource = {
  intermediateCertificateFile: string;
  /** Reads the key the subordinate signs its Entity Configuration with. */
  keyFile: string;
  /** True when `keyFile` is a JWKS to select a signing key out of, rather than a single JWK. */
  keyFileIsJwks: boolean;
  /**
   * How the published `kid` is arrived at, which must match what the subordinate
   * advertises for itself or a verifier cannot resolve the key through the Trust
   * Chain: `stored` keeps the `kid` in the key file, `thumbprint` recomputes it
   * as an RFC 7638 thumbprint the way the Wallet Provider's own `jwk` plugin
   * does.
   */
  kid: 'stored' | 'thumbprint';
  leafCertificateFile: string;
};

const SUBORDINATE_KEY_SOURCES = {
  issuer: {
    keyFile: join('issuer', 'jwks.json'),
    keyFileIsJwks: true,
    kid: 'stored',
    leafCertificateFile: join('issuer', 'cert.pem'),
    intermediateCertificateFile: join('issuer', 'intermediate-cert.pem')
  },
  // The subordinate statement must carry the key the Relying Party actually
  // signs its Entity Configuration with — its federation key, which lives in
  // its own file rather than as the second `use=sig` entry of `rp/jwks.json`,
  // and is certified by `federation-cert.pem` rather than by the self-signed
  // `cert.pem` covering its application key.
  rp: {
    keyFile: join('rp', 'federation-key.jwk.json'),
    keyFileIsJwks: false,
    kid: 'stored',
    leafCertificateFile: join('rp', 'federation-cert.pem'),
    intermediateCertificateFile: join('rp', 'intermediate-cert.pem')
  },
  walletProvider: {
    keyFile: join('wallet-provider', 'jwks.json'),
    keyFileIsJwks: true,
    kid: 'thumbprint',
    leafCertificateFile: join('wallet-provider', 'cert.pem'),
    intermediateCertificateFile: join('wallet-provider', 'intermediate-cert.pem')
  }
} as const satisfies Record<string, SubordinateKeySource>;

export type SubordinateName = keyof typeof SUBORDINATE_KEY_SOURCES;

/** Loads one subordinate's federation key as a subordinate statement publishes it.
 *
 * The leaf is checked against the key before the two are joined. The Trust
 * Anchor reads this material out of another service's directory, so it is the
 * one place a mismatch between a subordinate's key and its certificate can be
 * caught from the outside — and publishing them together is what would
 * otherwise hand a wallet a certificate for a key the subordinate does not sign
 * with.
 *
 * The private half is dropped here and never leaves this function: it is needed
 * to derive the public key and to compute the thumbprint `kid`, and for nothing
 * after that.
 */
async function loadSubordinatePublicJwk(dataDir: string, source: SubordinateKeySource): Promise<JsonWebKey> {
  const [privateJwk, leafCertificatePem, intermediateCertificatePem] = await Promise.all([
    source.keyFileIsJwks
      ? loadFederationJwkFromJwks(dataDir, source.keyFile)
      : loadFederationJwk(dataDir, source.keyFile),
    loadCertificate(dataDir, source.leafCertificateFile),
    loadCertificate(dataDir, source.intermediateCertificateFile)
  ]);

  try {
    await validateCertificateMatchesJwk(leafCertificatePem, privateJwk as JWK);
  } catch (err) {
    throw new Error(
      `${source.leafCertificateFile} does not certify the key in ${source.keyFile}: ` +
        `${err instanceof Error ? err.message : String(err)}. ` +
        `Run 'itw-conformance-tool init --force' to regenerate a coherent certificate chain.`
    );
  }

  const publicJwk =
    source.kid === 'thumbprint' ? await toThumbprintPublicJwk(privateJwk) : stripPrivateParams(privateJwk);

  return withCertificateChain(publicJwk, [leafCertificatePem, intermediateCertificatePem].map(convertPemToBase64Der));
}

export default fp(
  async function keysPlugin(app) {
    const { dataDir } = app.config;

    const subordinateNames = Object.keys(SUBORDINATE_KEY_SOURCES) as SubordinateName[];

    const [federationCertificatePem, federationPrivateJwk, ...subordinatePublicJwkList] = await Promise.all([
      loadCertificate(dataDir, join('trust-anchor', 'federation-cert.pem')),
      loadFederationJwk(dataDir, join('trust-anchor', 'federation-key.jwk.json')),
      ...subordinateNames.map((name) => loadSubordinatePublicJwk(dataDir, SUBORDINATE_KEY_SOURCES[name]))
    ]);

    app.decorate('trustAnchorKeys', {
      federationCertificateChain: [convertPemToBase64Der(federationCertificatePem)],
      federationPrivateJwk,
      subordinatePublicJwks: Object.fromEntries(
        subordinateNames.map((name, index) => [name, subordinatePublicJwkList[index]])
      ) as Record<SubordinateName, JsonWebKey>
    });
  },
  { name: 'keys', dependencies: ['config'] }
);
