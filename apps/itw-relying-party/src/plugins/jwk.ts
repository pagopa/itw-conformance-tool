import { readFile } from 'node:fs/promises';
import path from 'node:path';

import { convertPemToBase64Der, validateCertificateMatchesJwk } from '@itw-conformance-tool/crypto';
import fp from 'fastify-plugin';

import type { Jwk } from '@pagopa/io-wallet-oauth2';
import type { FastifyPluginAsync } from 'fastify';
import type { JWK } from 'jose';

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

/**
 * The three keys the Relying Party holds, separated by role rather than by
 * position in a key set.
 *
 * `sig` and `enc` are the *application* keys: they sign and encrypt Request
 * Objects and decrypt the Authorization Response. `federation` signs the Entity
 * Configuration and the Trust Mark, and nothing else. The split is what makes
 * the two trust mechanisms independent — a wallet resolving the Relying Party
 * through `x509_hash` never touches the federation key, and one resolving it
 * through the Trust Chain never touches the application keys' certificates.
 *
 * Each key is loaded from a file that admits only that role: the application
 * keys are selected out of `rp/jwks.json` by `use`, of which there is exactly
 * one apiece, and the federation key has a file to itself. They were previously
 * two `use=sig` entries in one JWKS told apart by array index, so reordering
 * them silently swapped which key signed what.
 */
type JwksByUse = Record<JwkUse, JwkKeyPair> & {
  federation: JwkKeyPair;
};

declare module 'fastify' {
  interface FastifyInstance {
    jwks: JwksByUse;
  }
}

const APPLICATION_JWKS_FILE = 'rp/jwks.json';
const FEDERATION_JWK_FILE = 'rp/federation-key.jwk.json';
const SIGNING_CERTIFICATE_FILE = 'rp/cert.pem';
const ENCRYPTION_CERTIFICATE_FILE = 'rp/enc-cert.pem';
const FEDERATION_CERTIFICATE_FILE = 'rp/federation-cert.pem';
const FEDERATION_INTERMEDIATE_CERTIFICATE_FILE = 'rp/intermediate-cert.pem';

const REMEDIATION = `Run 'itw-conformance-tool init --force' to regenerate a coherent Relying Party key set and certificate chain.`;

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

const parseJwk = (content: string, filePath: string): Jwk => {
  const jwk = JSON.parse(content) as unknown;

  if (typeof jwk !== 'object' || jwk === null || Array.isArray(jwk)) {
    throw new TypeError(`${filePath} must contain a single JWK object`);
  }

  return jwk as Jwk;
};

/**
 * Splits a private JWK into the pair the rest of the service uses, attaching
 * the certificate chain that certifies it to the public half.
 *
 * The chain travels on the public JWK because that is the half that gets
 * published — in the Entity Configuration, and in the Request Object
 * `client_metadata` — so a wallet reading a key out of either artifact also
 * receives the certificate binding it to its issuer.
 *
 * The leaf is checked against the key before either is used. Key material and
 * certificates are generated together by `itwct init` and are only coherent as a
 * set: regenerating one half alone would leave the Relying Party publishing a
 * certificate for a key it no longer signs with, a mismatch a wallet could only
 * discover as a signature that will not verify.
 */
const toKeyPair = async (jwk: Jwk, certificateChainPem: string[], role: string): Promise<JwkKeyPair> => {
  const privateJwk = jwk as PrivateJwk;
  const { d, key_ops, ...publicKey } = privateJwk;
  void d;
  void key_ops;

  try {
    await validateCertificateMatchesJwk(certificateChainPem[0], privateJwk as JWK);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`${role} does not certify the key it is published with. ${REMEDIATION} ${message}`);
  }

  return {
    private: privateJwk,
    public: { ...publicKey, x5c: certificateChainPem.map(convertPemToBase64Der) }
  };
};

/**
 * Selects the single key holding a given role out of the application JWKS.
 *
 * Exactly one match is required. Two would mean the role is ambiguous and the
 * key that ends up signing is decided by array order — the failure mode this
 * layout exists to remove — so it is rejected rather than resolved.
 */
const selectApplicationJwk = (jwks: Jwk[], use: JwkUse, alg: string, filePath: string): Jwk => {
  const matches = jwks.filter(
    (jwk) => jwk.kty === 'EC' && jwk.use === use && jwk.alg === alg && typeof jwk.d === 'string'
  );

  if (matches.length !== 1) {
    throw new Error(
      `${filePath} must contain exactly one private ${alg} JWK with use=${use}, found ${matches.length}. ${REMEDIATION}`
    );
  }

  return matches[0];
};

/** Reads a PEM file, reporting the missing artifact and how to regenerate it. */
const readCertificate = async (dataDir: string, relativePath: string): Promise<string> => {
  try {
    return await readFile(path.join(dataDir, relativePath), 'utf8');
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Unable to read ${relativePath}. ${REMEDIATION} ${message}`);
  }
};

const loadKeyPairs = async (dataDir: string): Promise<JwksByUse> => {
  const applicationJwksPath = path.join(dataDir, APPLICATION_JWKS_FILE);
  const federationJwkPath = path.join(dataDir, FEDERATION_JWK_FILE);

  const [applicationContent, federationContent] = await Promise.all([
    readFile(applicationJwksPath, 'utf8').catch((error: unknown) => {
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(`Unable to read ${APPLICATION_JWKS_FILE}. ${REMEDIATION} ${message}`);
    }),
    readFile(federationJwkPath, 'utf8').catch((error: unknown) => {
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(`Unable to read ${FEDERATION_JWK_FILE}. ${REMEDIATION} ${message}`);
    })
  ]);

  const applicationJwks = parseJwks(applicationContent, applicationJwksPath);

  const [signingCertificate, encryptionCertificate, federationCertificate, federationIntermediateCertificate] =
    await Promise.all([
      readCertificate(dataDir, SIGNING_CERTIFICATE_FILE),
      readCertificate(dataDir, ENCRYPTION_CERTIFICATE_FILE),
      readCertificate(dataDir, FEDERATION_CERTIFICATE_FILE),
      readCertificate(dataDir, FEDERATION_INTERMEDIATE_CERTIFICATE_FILE)
    ]);

  const [enc, federation, sig] = await Promise.all([
    toKeyPair(
      selectApplicationJwk(applicationJwks, 'enc', 'ECDH-ES', applicationJwksPath),
      [encryptionCertificate],
      ENCRYPTION_CERTIFICATE_FILE
    ),
    // Leaf first, and the Trust Anchor root left out: a verifier is expected to
    // hold the root already, and the issuer and Wallet Provider publish the same
    // shape.
    toKeyPair(
      parseJwk(federationContent, federationJwkPath),
      [federationCertificate, federationIntermediateCertificate],
      FEDERATION_CERTIFICATE_FILE
    ),
    toKeyPair(
      selectApplicationJwk(applicationJwks, 'sig', 'ES256', applicationJwksPath),
      [signingCertificate],
      SIGNING_CERTIFICATE_FILE
    )
  ]);

  return { enc, federation, sig };
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
