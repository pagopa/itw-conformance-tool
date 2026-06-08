import { createHash, createPrivateKey, generateKeyPairSync } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { DatabaseClient, SqliteNonceRepository, SqliteSessionRepository } from '@itw-conformance-tool/database';
import { SessionService } from '@itw-conformance-tool/rp';
import Fastify from 'fastify';
import { CompactEncrypt, SignJWT, importJWK, importPKCS8 } from 'jose';

import { generateEphemeralKeyPair } from '../../crypto/ephemeral-keys.js';

import type { INonceRepository } from '@itw-conformance-tool/database';
import type { FastifyPluginAsync } from 'fastify';
import type { JWK } from 'jose';

// ---------------------------------------------------------------------------
// Test key material (generated once per module load)
// ---------------------------------------------------------------------------

function generateEcPem() {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
}

export const TEST_AUTH_REQUEST_PEM = generateEcPem();
export const TEST_AUTH_RESPONSE_PEM = generateEcPem();
export const TEST_CLIENT_ID = 'http://localhost:8080';
export const TEST_BASE_PATH = 'http://localhost:8080';

// ---------------------------------------------------------------------------
// Helpers for building VP token payloads in tests
// ---------------------------------------------------------------------------

/**
 * Derives the public JWK from a PKCS8 PEM private key.
 * Removes the private `d` component so the result can be used for encryption.
 */
function publicJwkFromPem(pem: string): Record<string, unknown> {
  const privKey = createPrivateKey(pem);
  const { d: _d, ...pubJwk } = privKey.export({ format: 'jwk' }) as Record<string, unknown>;
  void _d;
  return pubJwk;
}

/**
 * Builds a compact JWE (ECDH-ES / A256GCM) containing a minimal VP token.
 * Suitable for testing POST /auth/response with a valid encrypted body.
 *
 * The SD-JWT contains no disclosures so sd_hash = sha256('').
 */
export async function createAuthResponseJwe({
  authResponsePrivateKeyPem = TEST_AUTH_RESPONSE_PEM,
  clientId = TEST_CLIENT_ID,
  kbJwtAlg = 'ES256',
  nonce,
  state
}: {
  authResponsePrivateKeyPem?: string;
  clientId?: string;
  kbJwtAlg?: 'ES256' | 'ES384' | 'ES512';
  nonce: string;
  state: string;
}): Promise<string> {
  // Derive the RP public key for encryption
  const rpPubJwk = publicJwkFromPem(authResponsePrivateKeyPem);
  const rpPubKey = await importJWK(rpPubJwk as unknown as JWK);

  // Holder key pair (signs the KB-JWT)
  const holderCurve = kbJwtAlg === 'ES256' ? 'P-256' : kbJwtAlg === 'ES384' ? 'P-384' : 'P-521';
  const { privateKey: holderPrivNode, publicKey: holderPubNode } = generateKeyPairSync('ec', {
    namedCurve: holderCurve
  });
  const holderPrivJose = await importPKCS8(
    holderPrivNode.export({ format: 'pem', type: 'pkcs8' }).toString(),
    kbJwtAlg
  );
  const holderPubJwk = holderPubNode.export({ format: 'jwk' }) as unknown as JWK;

  // Issuer key pair (signs the issuer SD-JWT)
  const { privateKey: issuerPrivNode } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const issuerPrivJose = await importPKCS8(issuerPrivNode.export({ format: 'pem', type: 'pkcs8' }).toString(), 'ES256');

  // SD-JWT with no disclosures: issuerJwt~kbJwt
  // sd_hash = sha256('') because there are no disclosures
  const issuerJwt = await new SignJWT({
    iss: 'https://issuer.example',
    vct: 'test',
    cnf: { jwk: holderPubJwk }
  })
    .setProtectedHeader({ alg: 'ES256', typ: 'dc+sd-jwt' })
    .sign(issuerPrivJose);
  const sdHash = createHash('sha256').update('').digest('base64url');

  const kbJwt = await new SignJWT({ aud: clientId, iat: Math.floor(Date.now() / 1000), nonce, sd_hash: sdHash })
    .setProtectedHeader({ alg: kbJwtAlg, typ: 'kb+jwt', jwk: holderPubJwk })
    .sign(holderPrivJose);

  const sdJwt = `${issuerJwt}~${kbJwt}`;

  // Encrypt { state, vp_token, presentation_submission } as ECDH-ES JWE
  const payload = new TextEncoder().encode(
    JSON.stringify({
      state,
      vp_token: { pid: sdJwt },
      presentation_submission: { id: 'test-submission' }
    })
  );
  return new CompactEncrypt(payload)
    .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM', kid: 'test-rp-key-id' })
    .encrypt(rpPubKey);
}

// ---------------------------------------------------------------------------
// Minimal in-memory nonce repository for simple route tests
// ---------------------------------------------------------------------------

export function createMemoryNonceRepository(): INonceRepository {
  const store = new Map<string, number>();
  return {
    async consume(value) {
      const expiresAt = store.get(value);
      if (expiresAt === undefined || expiresAt < Date.now()) {
        store.delete(value);
        return false;
      }
      store.delete(value);
      return true;
    },
    async delete(value) {
      store.delete(value);
    },
    async get(value) {
      const expiresAt = store.get(value);
      if (expiresAt === undefined || expiresAt < Date.now()) return undefined;
      return value;
    },
    async insert(value, expiresAtMs) {
      store.set(value, expiresAtMs);
    }
  };
}

// ---------------------------------------------------------------------------
// buildRpRouteApp — minimal Fastify app matching production decorator structure
// ---------------------------------------------------------------------------

export interface RpRouteAppOptions {
  authRequestPrivateKeyPem?: string;
  authResponsePrivateKeyPem?: string;
  baseUrl?: string;
}

/**
 * Builds a lightweight Fastify instance suitable for route-level tests.
 * Decorates with the same names used by production plugins:
 *   app.config, app.rpKeys, app.nonceRepository, app.sessionService
 */
export async function buildRpRouteApp(route: FastifyPluginAsync, options: RpRouteAppOptions = {}) {
  const dataDir = mkdtempSync(join(tmpdir(), 'rp-route-test-'));
  const dbClient = new DatabaseClient({ dataDir });
  const sessionRepo = new SqliteSessionRepository(dbClient.db);
  const nonceRepo = new SqliteNonceRepository(dbClient.db);
  const sessionService = new SessionService(sessionRepo);
  const ephemeralKeys = await generateEphemeralKeyPair();

  const app = Fastify({ logger: false });

  app.decorate('config', {
    host: '0.0.0.0',
    port: 8080,
    baseUrl: options.baseUrl ?? TEST_CLIENT_ID,
    entityId: options.baseUrl ?? TEST_CLIENT_ID,
    dataDir,
    configFilePath: join(dataDir, 'config.ini'),
    trustAnchorUrl: 'https://trust-anchor.example.com',
    signingKeyPath: join(dataDir, 'signing-key.pem'),
    x5cCertPath: join(dataDir, 'x5c-cert.pem'),
    httpsEnabled: false,
    tlsCertPath: join(dataDir, 'tls_cert.pem'),
    tlsKeyPath: join(dataDir, 'tls_key.pem')
  });

  app.decorate('rpKeys', {
    authRequestPrivateKeyPem: options.authRequestPrivateKeyPem ?? TEST_AUTH_REQUEST_PEM,
    authResponsePrivateKeyPem: options.authResponsePrivateKeyPem ?? TEST_AUTH_RESPONSE_PEM,
    signingPrivateKeyPem: TEST_AUTH_REQUEST_PEM,
    x5cCertPem: '-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----\n'
  });

  app.decorate('trustChain', ['insecure-http-local-dev']);
  app.decorate('ephemeralKeys', ephemeralKeys);
  app.decorate('nonceRepository', nonceRepo);
  app.decorate('sessionService', sessionService);

  app.addHook('onClose', async () => {
    await dbClient.close();
    await rm(dataDir, { recursive: true, force: true });
  });

  await app.register(route);
  await app.ready();

  return { app, dbClient, nonceRepo, sessionService };
}
