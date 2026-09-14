import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  convertPemToBase64Der,
  getCertificateChainPublicKey,
  validateCertificateChain
} from '@itw-conformance-tool/crypto';
import { BasicConstraintsExtension, KeyUsageFlags, KeyUsagesExtension, X509Certificate } from '@peculiar/x509';
import Fastify, { type FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';
import issuerBootstrap from 'itw-credential-issuer/src/app.js';
import relyingPartyBootstrap from 'itw-relying-party/src/app.js';
import trustAnchorBootstrap from 'itw-trust-anchor/src/app.js';
import walletProviderBootstrap from 'itw-wallet-provider/src/app.js';
import { createLocalJWKSet, decodeJwt, decodeProtectedHeader, jwtVerify } from 'jose';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

import { init } from '../commands/init.js';

/**
 * Boots each local service against key material `init` has just generated and
 * checks what it publishes at `/.well-known/openid-federation`.
 *
 * The unit tests in `certificates.test.ts` cover the certificates in isolation —
 * that a chain built from a set of keys links up. They cannot see the two things
 * that broke in practice: whether a service actually publishes the certificate
 * next to the key it certifies, and whether the certificate it publishes is the
 * one that certifies the key it is signing with. Both are wiring between three
 * separate artifacts on disk (a key file, a certificate file, and the service
 * that reads them), so they are only observable from a running service.
 *
 * Each service is started in-process with `app.inject` rather than over a port:
 * the plugins under test — the Trust Anchor's `keys`, the Relying Party's `jwk`,
 * the Wallet Provider's `jwk` — run exactly as they do in production, while the
 * test binds nothing and needs no TLS.
 */

/** How a service is booted and which certificates certify its federation key. */
type FederationEntity = {
  /** The app bootstrap, registered into a bare Fastify instance. */
  bootstrap: Parameters<typeof fp>[0];
  /**
   * The certificates, relative to the data directory, that certify the key the
   * service signs its Entity Configuration with. The Trust Anchor publishes
   * this chain as the key's `x5c` in every subordinate statement, whether or
   * not the service publishes it itself.
   */
  federationChain: { intermediate: string; leaf: string };
  name: string;
  /**
   * Whether the service publishes `federationChain` as the `x5c` of the key in
   * its own Entity Configuration. False for a service that publishes the bare
   * key: its chain still exists on disk and in the Trust Anchor's statement
   * about it, but nothing in its own Entity Configuration points at it.
   */
  publishesFederationChain: boolean;
};

/**
 * The three subordinate entities. Each signs its Entity Configuration with a
 * leaf certified by its own intermediate CA, which the Trust Anchor certifies in
 * turn, so each roots at the same certificate.
 *
 * Only the issuer and the Relying Party publish that chain as an `x5c` beside
 * the key. The Wallet Provider's chain reaches a verifier through the Wallet
 * Instance Attestation header instead, so its Entity Configuration carries the
 * bare key and the assertions about published chains below leave it out. That it
 * signs with the key `wallet-provider/cert.pem` certifies is still checked — by
 * its own `jwk` plugin, at the boot every test here depends on.
 */
const SUBORDINATE_ENTITIES: FederationEntity[] = [
  {
    name: 'credential-issuer',
    bootstrap: issuerBootstrap,
    federationChain: {
      leaf: join('issuer', 'cert.pem'),
      intermediate: join('issuer', 'intermediate-cert.pem')
    },
    publishesFederationChain: true
  },
  {
    name: 'relying-party',
    bootstrap: relyingPartyBootstrap,
    federationChain: {
      leaf: join('rp', 'federation-cert.pem'),
      intermediate: join('rp', 'intermediate-cert.pem')
    },
    publishesFederationChain: true
  },
  {
    name: 'wallet-provider',
    bootstrap: walletProviderBootstrap,
    federationChain: {
      leaf: join('wallet-provider', 'cert.pem'),
      intermediate: join('wallet-provider', 'intermediate-cert.pem')
    },
    publishesFederationChain: false
  }
];

/** The subordinate entities that publish a certificate chain beside their key. */
const CHAIN_PUBLISHING_ENTITIES = SUBORDINATE_ENTITIES.filter((entity) => entity.publishesFederationChain);

const TRUST_ANCHOR_FEDERATION_CERTIFICATE = join('trust-anchor', 'federation-cert.pem');

type PublishedJwk = {
  crv?: string;
  kid?: string;
  kty?: string;
  use?: string;
  x?: string;
  x5c?: string[];
  y?: string;
};

type EntityConfigurationClaims = {
  iss: string;
  jwks: { keys: PublishedJwk[] };
  metadata: Record<string, { jwks?: { keys: PublishedJwk[] } } | undefined>;
};

let dataDir: string;
/** Signed Entity Configuration JWT served by each service, keyed by service name. */
const entityConfigurations = new Map<string, string>();
/** Subordinate statement the Trust Anchor issues for each service, keyed the same way. */
const subordinateStatements = new Map<string, string>();

function certificateOnDisk(relativePath: string): string {
  return readFileSync(join(dataDir, relativePath), 'utf8');
}

/** The base64 DER form an `x5c` entry carries, for the certificate on disk. */
function publishedForm(relativePath: string): string {
  return convertPemToBase64Der(certificateOnDisk(relativePath));
}

function toDer(base64Der: string): ArrayBuffer {
  const bytes = Uint8Array.from(Buffer.from(base64Der, 'base64'));
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

/** Parses an `x5c` entry back into the certificate a verifier would read. */
function publishedCertificate(base64Der: string): X509Certificate {
  return new X509Certificate(toDer(base64Der));
}

/**
 * The constraints path validation applies to a certificate, beyond its
 * signature: whether it may sign certificates at all, and how many may sit
 * below it.
 *
 * They are read separately from the chain walk below because
 * `validateCertificateChain` only follows signatures and validity dates. A root
 * that is not a CA — which the Trust Anchor certificate was, with an
 * `encipherOnly` key usage — passes that walk and is still refused by every
 * standards-compliant verifier, `openssl verify` included.
 */
function certificateConstraints(certificate: X509Certificate): {
  isCertificateAuthority: boolean;
  pathLength?: number;
  usages: number;
} {
  const basicConstraints = certificate.getExtension(BasicConstraintsExtension);

  return {
    isCertificateAuthority: basicConstraints?.ca ?? false,
    pathLength: basicConstraints?.pathLength,
    usages: certificate.getExtension(KeyUsagesExtension)?.usages ?? 0
  };
}

function claims(entityConfiguration: string): EntityConfigurationClaims {
  return decodeJwt(entityConfiguration) as unknown as EntityConfigurationClaims;
}

/** The single key an Entity Configuration publishes as its federation key. */
function federationJwk(serviceName: string): PublishedJwk {
  const { jwks } = claims(entityConfigurations.get(serviceName) as string);
  expect(jwks.keys).toHaveLength(1);
  return jwks.keys[0];
}

function metadataJwks(serviceName: string, entityType: string): PublishedJwk[] {
  const keys = claims(entityConfigurations.get(serviceName) as string).metadata[entityType]?.jwks?.keys;
  if (!keys) throw new Error(`${serviceName} publishes no ${entityType} JWKS`);
  return keys;
}

/**
 * Asserts that the leaf of `jwk.x5c` certifies `jwk` itself.
 *
 * A certificate published next to a key it does not belong to is the failure a
 * wallet can only discover as a signature that will not verify, so the binding
 * is checked by deriving the key back out of the certificate — the same way a
 * verifier reading the `x5c` would.
 */
async function expectLeafCertifies(jwk: PublishedJwk): Promise<void> {
  const certifiedKey = await getCertificateChainPublicKey({ alg: 'ES256', certificateChain: jwk.x5c as string[] });

  expect(certifiedKey).toMatchObject({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
}

/** Starts a service, hands it to `use`, and shuts it down again. */
async function withService<T>(
  bootstrap: FederationEntity['bootstrap'],
  use: (app: FastifyInstance) => Promise<T>
): Promise<T> {
  const app = Fastify({ logger: false });
  await app.register(fp(bootstrap));
  await app.ready();

  try {
    return await use(app);
  } finally {
    await app.close();
  }
}

async function readEntityConfiguration(app: FastifyInstance, serviceName: string): Promise<string> {
  const response = await app.inject({ method: 'GET', url: '/.well-known/openid-federation' });

  expect(response.statusCode, `${serviceName} must serve its Entity Configuration`).toBe(200);
  expect(response.headers['content-type']).toMatch(/^application\/entity-statement\+jwt/);

  return response.body;
}

beforeAll(async () => {
  // `init` reads config.ini from the working directory and resolves the data
  // directory against it, so a temporary working directory gives the whole
  // federation — config, keys, certificates — a disposable home, and the
  // services booted below load exactly what it wrote.
  const workingDirectory = mkdtempSync(join(tmpdir(), 'itwct-federation-certificates-'));
  process.chdir(workingDirectory);

  const stdout = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
  try {
    await init({ force: true });
  } finally {
    stdout.mockRestore();
  }

  dataDir = join(workingDirectory, '.itw-conformance-tool');

  for (const entity of SUBORDINATE_ENTITIES) {
    // One service at a time: they share a SQLite database in the data directory,
    // and a temporary federation is not the place to discover concurrency
    // problems that production, with one service per process, does not have.
    entityConfigurations.set(
      entity.name,
      await withService(entity.bootstrap, (app) => readEntityConfiguration(app, entity.name))
    );
  }

  await withService(trustAnchorBootstrap, async (app) => {
    entityConfigurations.set('trust-anchor', await readEntityConfiguration(app, 'trust-anchor'));

    for (const entity of SUBORDINATE_ENTITIES) {
      // Asked for by the Entity ID the service itself published, which is how a
      // wallet building a Trust Chain arrives at this endpoint.
      const subject = claims(entityConfigurations.get(entity.name) as string).iss;
      const response = await app.inject({ method: 'GET', url: `/fetch?sub=${encodeURIComponent(subject)}` });

      expect(response.statusCode, `the Trust Anchor must attest ${entity.name}`).toBe(200);
      subordinateStatements.set(entity.name, response.body);
    }
  });
}, 120_000);

afterAll(() => {
  const workingDirectory = process.cwd();
  // Vitest starts each test file in the package root; going back leaves the
  // process where the next file expects to find itself.
  process.chdir(join(import.meta.dirname, '..', '..'));
  rmSync(workingDirectory, { recursive: true, force: true });
});

describe('Trust Anchor Entity Configuration', () => {
  it('publishes the federation certificate alongside the key it certifies', async () => {
    const jwk = federationJwk('trust-anchor');

    // A single-element chain: the Trust Anchor certificate is self-signed, and
    // publishing it here is what lets a verifier obtain the root of every local
    // chain from the federation instead of out of band.
    expect(jwk.x5c).toEqual([publishedForm(TRUST_ANCHOR_FEDERATION_CERTIFICATE)]);
    await expectLeafCertifies(jwk);
  });

  it('signs the Entity Configuration with the key the published certificate certifies', async () => {
    const entityConfiguration = entityConfigurations.get('trust-anchor') as string;
    const jwk = federationJwk('trust-anchor');

    expect(decodeProtectedHeader(entityConfiguration).kid).toBe(jwk.kid);
    await expect(jwtVerify(entityConfiguration, createLocalJWKSet({ keys: [jwk] }))).resolves.toBeDefined();
  });

  it('publishes a root allowed to sign the certificates beneath it', () => {
    const { isCertificateAuthority, pathLength, usages } = certificateConstraints(
      publishedCertificate((federationJwk('trust-anchor').x5c as string[])[0])
    );

    // The defect this suite exists for: the published root used to be a leaf
    // (`CA:FALSE`, `encipherOnly`), so every chain hanging off it failed path
    // validation — "key usage does not include certificate signing" — while its
    // signatures were perfectly sound.
    expect(isCertificateAuthority).toBe(true);
    expect(usages & KeyUsageFlags.keyCertSign).toBeTruthy();
    // One intermediate is expected to sit between this root and each leaf, so
    // the path length must leave room for it.
    expect(pathLength ?? Number.POSITIVE_INFINITY).toBeGreaterThanOrEqual(1);
  });

  it('is the certificate the subordinate chains terminate at', async () => {
    const trustAnchorCertificate = publishedCertificate((federationJwk('trust-anchor').x5c as string[])[0]);

    for (const entity of CHAIN_PUBLISHING_ENTITIES) {
      const intermediate = publishedCertificate((federationJwk(entity.name).x5c as string[])[1]);

      // Checked cryptographically rather than by subject name: an intermediate
      // naming the Trust Anchor as its issuer without being signed by it is
      // exactly what path validation exists to reject.
      await expect(
        intermediate.verify({ publicKey: await trustAnchorCertificate.publicKey.export() }),
        `${entity.name} intermediate must be signed by the Trust Anchor`
      ).resolves.toBe(true);
    }
  });
});

describe.each(SUBORDINATE_ENTITIES)('$name Entity Configuration', (entity) => {
  it('signs the Entity Configuration with the key it publishes', async () => {
    const entityConfiguration = entityConfigurations.get(entity.name) as string;
    const jwk = federationJwk(entity.name);

    expect(decodeProtectedHeader(entityConfiguration).kid).toBe(jwk.kid);
    await expect(jwtVerify(entityConfiguration, createLocalJWKSet({ keys: [jwk] }))).resolves.toBeDefined();
  });

  it('is attested by the Trust Anchor under the key it signs with', () => {
    const attestedKeys = claims(subordinateStatements.get(entity.name) as string).jwks.keys;
    const { crv, kty, x, y } = federationJwk(entity.name);

    // The Trust Anchor reads this key from its own copy of the entity's key
    // material, so it is a second, independent answer to "which key does this
    // entity sign with" — and the only place a mismatch shows up is here, as a
    // Trust Chain that resolves to a key nothing signed with. The Relying Party
    // is the reason: its federation key and its Request Object signing key were
    // once two `use=sig` entries in one file, told apart by array position.
    //
    // The statement also carries the Trust Anchor's own key, which is what
    // verifies the statement itself, so the subject's key is looked for rather
    // than expected alone.
    expect(attestedKeys).toContainEqual(expect.objectContaining({ crv, kty, x, y }));
  });
});

describe.each(SUBORDINATE_ENTITIES)('$name subordinate statement', (entity) => {
  /** The keys the Trust Anchor's statement about this entity publishes. */
  function attestedKeys(): PublishedJwk[] {
    return claims(subordinateStatements.get(entity.name) as string).jwks.keys;
  }

  it('publishes the subject chain beside the subject key', async () => {
    const { crv, kty, x, y } = federationJwk(entity.name);
    const subjectKey = attestedKeys().find((key) => key.crv === crv && key.kty === kty && key.x === x && key.y === y);
    if (!subjectKey) throw new Error(`the Trust Anchor does not attest ${entity.name}'s federation key`);

    // Read from the Trust Anchor's own copy of the entity's certificate files,
    // which is a second, independent answer to "which certificate certifies
    // this key" — and, for the Wallet Provider, the only place the chain is
    // published beside the key at all: its own Entity Configuration carries the
    // bare key.
    expect(subjectKey.x5c).toEqual([
      publishedForm(entity.federationChain.leaf),
      publishedForm(entity.federationChain.intermediate)
    ]);
    await expectLeafCertifies(subjectKey);
  });

  it('publishes the Trust Anchor chain beside the key that signed the statement', async () => {
    const statement = subordinateStatements.get(entity.name) as string;
    const signingKid = decodeProtectedHeader(statement).kid;
    const signingKey = attestedKeys().find((key) => key.kid === signingKid);
    if (!signingKey) throw new Error(`${entity.name}'s statement does not publish the key that signed it`);

    // The statement is self-contained: a verifier holding it can check the
    // signature and the certificate behind the signing key without fetching the
    // Trust Anchor's own Entity Configuration first.
    expect(signingKey.x5c).toEqual([publishedForm(TRUST_ANCHOR_FEDERATION_CERTIFICATE)]);
    await expectLeafCertifies(signingKey);
    await expect(jwtVerify(statement, createLocalJWKSet({ keys: [signingKey] }))).resolves.toBeDefined();
  });

  it('publishes chains that validate up to the Trust Anchor', async () => {
    const trustAnchorForm = publishedForm(TRUST_ANCHOR_FEDERATION_CERTIFICATE);
    const trustAnchorCertificate = toDer(trustAnchorForm);

    for (const jwk of attestedKeys()) {
      const published = jwk.x5c as string[];
      // Every key in the statement, the Trust Anchor's own included. Its chain
      // is the root itself, so the root a verifier supplies is already the last
      // link rather than one to append — appending it would hand the walk the
      // same certificate twice.
      const x5chain = [
        ...published.map(toDer),
        ...(published[published.length - 1] === trustAnchorForm ? [] : [trustAnchorCertificate])
      ];

      await expect(
        validateCertificateChain({
          trustedCertificates: [trustAnchorCertificate],
          x5chain: x5chain as [ArrayBuffer, ...ArrayBuffer[]]
        }),
        `${jwk.kid} must chain to the Trust Anchor`
      ).resolves.toBeUndefined();
    }
  });
});

describe.each(CHAIN_PUBLISHING_ENTITIES)('$name published certificate chain', (entity) => {
  it('publishes the leaf and intermediate certificates for its federation key', async () => {
    const jwk = federationJwk(entity.name);

    // Leaf first, and the Trust Anchor left out: a verifier is expected to hold
    // the root already, so publishing it would add a certificate the verifier
    // must ignore rather than one it can use.
    expect(jwk.x5c).toEqual([
      publishedForm(entity.federationChain.leaf),
      publishedForm(entity.federationChain.intermediate)
    ]);
    await expectLeafCertifies(jwk);
  });

  it('publishes a chain that validates up to the certificate the Trust Anchor publishes', async () => {
    const jwk = federationJwk(entity.name);
    // The root a verifier supplies is the one it read from the Trust Anchor's
    // own Entity Configuration, not the file on disk: what the federation
    // publishes has to be what the chains actually root at.
    const trustAnchorCertificate = toDer((federationJwk('trust-anchor').x5c as string[])[0]);
    const publishedChain = (jwk.x5c as string[]).map(toDer);

    // Walks the chain the way the services themselves do — every certificate
    // signed by the next one up, every one of them current — ending at the root
    // the verifier holds. The constraints that walk does not check are asserted
    // below.
    await expect(
      validateCertificateChain({
        trustedCertificates: [trustAnchorCertificate],
        x5chain: [...publishedChain, trustAnchorCertificate] as [ArrayBuffer, ...ArrayBuffer[]]
      })
    ).resolves.toBeUndefined();
  });

  it('publishes an intermediate allowed to certify the leaf it accompanies', () => {
    const [leaf, intermediate] = (federationJwk(entity.name).x5c as string[]).map(publishedCertificate);

    const intermediateConstraints = certificateConstraints(intermediate);
    expect(intermediateConstraints.isCertificateAuthority).toBe(true);
    expect(intermediateConstraints.usages & KeyUsageFlags.keyCertSign).toBeTruthy();

    // The leaf ends the chain: it signs Entity Configurations, and a verifier
    // must refuse anything it purports to certify.
    const leafConstraints = certificateConstraints(leaf);
    expect(leafConstraints.isCertificateAuthority).toBe(false);
    expect(leafConstraints.usages & KeyUsageFlags.digitalSignature).toBeTruthy();
  });
});

describe('Credential Issuer published keys', () => {
  const ISSUER_SIGNING_CHAIN = [join('issuer', 'cert.pem'), join('issuer', 'intermediate-cert.pem')];
  const ISSUER_ENCRYPTION_CHAIN = [join('issuer', 'enc-cert.pem'), join('issuer', 'intermediate-cert.pem')];

  /** Every metadata JWKS the Credential Issuer's Entity Configuration carries. */
  function publishedMetadataKeys(): PublishedJwk[] {
    return ['oauth_authorization_server', 'openid_credential_issuer', 'openid_credential_verifier'].flatMap(
      (entityType) => metadataJwks('credential-issuer', entityType)
    );
  }

  it('publishes a certificate chain beside every key in its metadata', async () => {
    // The signing key is published in three separate metadata blocks and the
    // encryption key in one, each of which used to be free to publish a bare
    // key: only the top-level federation JWKS attached a chain. A wallet reading
    // a key out of any of them now receives the certificate binding it to the
    // Credential Issuer.
    const publishedKeys = publishedMetadataKeys();
    expect(publishedKeys.length).toBeGreaterThan(0);

    for (const jwk of publishedKeys) {
      const expectedChain = jwk.use === 'enc' ? ISSUER_ENCRYPTION_CHAIN : ISSUER_SIGNING_CHAIN;

      expect(jwk.x5c, `${jwk.kid} must publish its certificate chain`).toEqual(expectedChain.map(publishedForm));
      await expectLeafCertifies(jwk);
    }
  });

  it('certifies its encryption key separately from its signing key', async () => {
    const [signingJwk, encryptionJwk] = ['sig', 'enc'].map((use) => {
      const jwk = metadataJwks('credential-issuer', 'openid_credential_verifier').find((key) => key.use === use);
      if (!jwk) throw new Error(`the Credential Issuer publishes no ${use} key`);
      return jwk;
    });

    // Two keys, two leaves, one intermediate. Publishing the signing leaf beside
    // the encryption key would point a wallet at a key it cannot encrypt to.
    expect(signingJwk.x5c).toEqual(ISSUER_SIGNING_CHAIN.map(publishedForm));
    expect(encryptionJwk.x5c).toEqual(ISSUER_ENCRYPTION_CHAIN.map(publishedForm));
    await expectLeafCertifies(encryptionJwk);
  });

  it('roots every published key at the certificate the Relying Party chain roots at', async () => {
    const trustAnchorCertificate = toDer((federationJwk('trust-anchor').x5c as string[])[0]);

    for (const jwk of publishedMetadataKeys()) {
      const publishedChain = (jwk.x5c as string[]).map(toDer);

      // The same root, reached by the same walk, as the Relying Party's
      // federation chain — the Credential Issuer publishes both of its keys
      // inside the federation, so neither is certified outside it.
      await expect(
        validateCertificateChain({
          trustedCertificates: [trustAnchorCertificate],
          x5chain: [...publishedChain, trustAnchorCertificate] as [ArrayBuffer, ...ArrayBuffer[]]
        }),
        `${jwk.kid} must chain to the Trust Anchor`
      ).resolves.toBeUndefined();
    }
  });
});

describe('Relying Party application keys', () => {
  it('publishes each application key with its own self-signed certificate', async () => {
    const [signingJwk, encryptionJwk] = ['sig', 'enc'].map((use) => {
      const jwk = metadataJwks('relying-party', 'openid_credential_verifier').find((key) => key.use === use);
      if (!jwk) throw new Error(`the Relying Party publishes no ${use} key`);
      return jwk;
    });

    expect(signingJwk.x5c).toEqual([publishedForm(join('rp', 'cert.pem'))]);
    expect(encryptionJwk.x5c).toEqual([publishedForm(join('rp', 'enc-cert.pem'))]);
    await expectLeafCertifies(signingJwk);
    await expectLeafCertifies(encryptionJwk);
  });

  it('keeps the application certificates outside the federation', async () => {
    const trustAnchorCertificate = publishedCertificate((federationJwk('trust-anchor').x5c as string[])[0]);
    const applicationKeys = metadataJwks('relying-party', 'openid_credential_verifier');

    for (const jwk of applicationKeys) {
      const certificate = publishedCertificate((jwk.x5c as string[])[0]);

      // Self-signed on purpose: a wallet that resolves the Relying Party through
      // `x509_hash` commits to this certificate and is deliberately not being
      // pointed at the Trust Anchor, so the two trust mechanisms stay
      // independent.
      await expect(certificate.verify({ publicKey: await certificate.publicKey.export() })).resolves.toBe(true);
      await expect(certificate.verify({ publicKey: await trustAnchorCertificate.publicKey.export() })).resolves.toBe(
        false
      );
    }
  });
});
