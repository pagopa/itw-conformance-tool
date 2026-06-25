import { createHash, createPrivateKey, createPublicKey, randomUUID } from 'node:crypto';

import { getX5cCert } from '@itw-conformance-tool/crypto';
import { createItWalletEntityConfiguration } from '@pagopa/io-wallet-oid-federation';
import { PemConverter, X509Certificate } from '@peculiar/x509';
import {
  SignJWT,
  calculateJwkThumbprint,
  decodeJwt,
  decodeProtectedHeader,
  exportJWK,
  generateKeyPair,
  importJWK,
  jwtVerify
} from 'jose';

import { signJwtCallback } from '../../federation/signer.js';

import type { FastifyInstance, FastifyPluginAsync, FastifyReply } from 'fastify';
import type { JWK } from 'jose';

const ATTESTATION_TTL_SECONDS = 3600;
const PII_CLAIMS = new Set([
  'given_name',
  'family_name',
  'email',
  'phone_number',
  'birthdate',
  'address',
  'fiscal_code',
  'tax_id',
  'national_id',
  'personal_id'
]);

export type FederationAccessLogEntry = {
  method: string;
  path: string;
  timestamp: string;
};

export type AttestationIssuanceLogEntry = {
  ephemeralKeyThumbprint: string;
  timestamp: string;
};

export type RevocationNotificationEvent = {
  instanceId: string;
  revokedAt: string;
  notifiedAt: string;
};

export type WalletProviderSimulatorState = {
  baseUrl: string;
  federationPrivateKeyPem: string;
  x5cCertPem: string;
  entityConfigurationJwt?: string;
  seenEphemeralKeyThumbprints: Set<string>;
  nonces: Map<string, number>;
  instances: Map<string, { ownerToken: string; status: 'ACTIVE' | 'REVOKED'; issuedAt: string }>;
  federationAccessLog: FederationAccessLogEntry[];
  attestationIssuanceLog: AttestationIssuanceLogEntry[];
  revocationNotifications: RevocationNotificationEvent[];
};

function parseCertificateChain(pemChain: string): string[] {
  return PemConverter.decode(pemChain).map((rawCertificate) => {
    const certificate = new X509Certificate(rawCertificate);
    return Buffer.from(certificate.rawData).toString('base64');
  });
}

async function toPublicJwk(privateKeyPem: string, x5c?: string[]): Promise<JWK> {
  const publicJwk = createPublicKey(createPrivateKey(privateKeyPem)).export({ format: 'jwk' }) as JWK;
  const kid = await calculateJwkThumbprint(publicJwk);
  return { ...publicJwk, kid, ...(x5c && x5c.length > 0 ? { x5c } : {}) };
}

async function toPrivateJwk(privateKeyPem: string, kid: string): Promise<JWK> {
  const privateJwk = createPrivateKey(privateKeyPem).export({ format: 'jwk' }) as JWK;
  return { ...privateJwk, kid };
}

function sendError(reply: FastifyReply, statusCode: number, error: string, errorDescription: string) {
  return reply
    .code(statusCode)
    .header('Content-Type', 'application/json')
    .send({ error, error_description: errorDescription });
}

function extractBearerToken(authorization?: string): string | undefined {
  if (!authorization?.startsWith('Bearer ')) return undefined;
  return authorization.slice('Bearer '.length).trim() || undefined;
}

function isMaintenanceMode(headers: Record<string, unknown>): boolean {
  return headers['x-test-maintenance'] === 'true';
}

function isSimulatedServerError(headers: Record<string, unknown>): boolean {
  return headers['x-test-server-error'] === 'true';
}

function recordFederationAccess(state: WalletProviderSimulatorState, method: string, path: string): void {
  state.federationAccessLog.push({ method, path, timestamp: new Date().toISOString() });
}

function recordAttestationIssuance(state: WalletProviderSimulatorState, ephemeralKeyThumbprint: string): void {
  state.attestationIssuanceLog.push({
    ephemeralKeyThumbprint,
    timestamp: new Date().toISOString()
  });
}

function recordRevocationNotification(state: WalletProviderSimulatorState, instanceId: string): void {
  const revokedAt = new Date().toISOString();
  state.revocationNotifications.push({
    instanceId,
    revokedAt,
    notifiedAt: new Date().toISOString()
  });
}

function deviceFailsIntegrityChecks(assertionPayload: Record<string, unknown>): boolean {
  return assertionPayload.integrity_assertion === 'compromised-device';
}

function deviceHasKnownSecurityFlaw(assertionPayload: Record<string, unknown>): boolean {
  return (
    assertionPayload.hardware_signature === 'invalid-security-flaw' ||
    assertionPayload.platform === 'compromised-platform'
  );
}

export async function createWalletProviderEntityConfiguration(state: WalletProviderSimulatorState): Promise<string> {
  const issuedAt = Math.floor(Date.now() / 1000);
  const federationSigningJwk = await toPublicJwk(state.federationPrivateKeyPem);
  const signingKid = federationSigningJwk.kid;
  if (!signingKid) {
    throw new Error('Federation signing key is missing kid');
  }
  const signingPrivateJwk = await toPrivateJwk(state.federationPrivateKeyPem, signingKid);

  return createItWalletEntityConfiguration({
    claims: {
      authority_hints: [new URL(state.baseUrl).origin],
      exp: issuedAt + 3600,
      iat: issuedAt,
      iss: state.baseUrl,
      jwks: { keys: [federationSigningJwk] },
      metadata: {
        federation_entity: {
          contacts: ['info@pagopa.it'],
          homepage_uri: 'https://io.italia.it',
          logo_uri: 'https://io.italia.it/assets/img/io-it-logo-blue.svg',
          organization_name: 'PagoPa S.p.A.',
          policy_uri: 'https://io.italia.it/privacy-policy'
        },
        wallet_provider: {
          aal_values_supported: ['https://example.com/LoA/basic'],
          grant_types_supported: ['urn:ietf:params:oauth:client-assertion-type:jwt-bearer'],
          jwks: { keys: [federationSigningJwk] },
          token_endpoint: `${state.baseUrl}/token`,
          token_endpoint_auth_methods_supported: ['private_key_jwt'],
          token_endpoint_auth_signing_alg_values_supported: ['ES256']
        }
      },
      sub: state.baseUrl,
      trust_marks: []
    },
    header: {
      alg: 'ES256',
      kid: federationSigningJwk.kid,
      typ: 'entity-statement+jwt'
    },
    signJwtCallback: async ({ toBeSigned }) => signJwtCallback({ jwk: signingPrivateJwk, toBeSigned })
  });
}

export async function issueWalletAttestationJwt(
  state: WalletProviderSimulatorState,
  holderPublicJwk: JWK
): Promise<string> {
  const issuedAt = Math.floor(Date.now() / 1000);
  const x5c = parseCertificateChain(state.x5cCertPem);
  const federationSigningJwk = await toPublicJwk(state.federationPrivateKeyPem, x5c);
  const signingKid = federationSigningJwk.kid;
  if (!signingKid) {
    throw new Error('Federation signing key is missing kid');
  }
  const signingPrivateJwk = await toPrivateJwk(state.federationPrivateKeyPem, signingKid);
  const signingKey = await importJWK(signingPrivateJwk, 'ES256');
  const sub = await calculateJwkThumbprint(holderPublicJwk);

  return new SignJWT({
    cnf: { jwk: holderPublicJwk },
    status: { status_list: { idx: 0, uri: `${state.baseUrl}/statuslist` } },
    wallet_link: `${state.baseUrl}/wallet`,
    wallet_name: 'IT-Wallet Conformance',
    eudi_wallet_info: {
      general_info: {
        wallet_provider_name: 'Conformance Tool WP',
        wallet_solution_id: 'itw-conformance-wallet',
        wallet_solution_version: '1.0.0',
        wallet_solution_certification_information: 'https://example.com/certification'
      }
    }
  })
    .setProtectedHeader({
      alg: 'ES256',
      kid: signingKid,
      typ: 'oauth-client-attestation+jwt',
      x5c
    })
    .setIssuer(state.baseUrl)
    .setSubject(sub)
    .setIssuedAt(issuedAt)
    .setExpirationTime(issuedAt + ATTESTATION_TTL_SECONDS)
    .sign(signingKey);
}

export function createWalletProviderSimulatorPlugin(getState: () => WalletProviderSimulatorState): FastifyPluginAsync {
  return async (app) => {
    app.addHook('onRequest', async (request, reply) => {
      if (isMaintenanceMode(request.headers)) {
        return sendError(reply, 503, 'temporarily_unavailable', 'Service temporarily unavailable');
      }
      if (isSimulatedServerError(request.headers)) {
        return sendError(reply, 500, 'server_error', 'Internal server error');
      }
    });

    app.get('/nonce', async (_request, reply) => {
      const state = getState();
      const nonce = randomUUID();
      state.nonces.set(nonce, Date.now() + 300_000);
      return reply.code(200).header('Content-Type', 'application/json').send({ nonce });
    });

    app.get('/.well-known/openid-federation', async (request, reply) => {
      const state = getState();
      recordFederationAccess(state, request.method, request.url);
      if (!state.entityConfigurationJwt) {
        state.entityConfigurationJwt = await createWalletProviderEntityConfiguration(state);
      }
      return reply
        .code(200)
        .header('Content-Type', 'application/entity-statement+jwt')
        .send(state.entityConfigurationJwt);
    });

    app.post('/fetch', async (request, reply) => {
      const body = request.body as { entity_id?: string } | undefined;
      if (!body?.entity_id) {
        return sendError(reply, 400, 'bad_request', 'entity_id is required');
      }

      const state = getState();
      recordFederationAccess(state, request.method, request.url);
      if (!state.entityConfigurationJwt) {
        state.entityConfigurationJwt = await createWalletProviderEntityConfiguration(state);
      }

      return reply
        .code(200)
        .header('Content-Type', 'application/entity-statement+jwt')
        .send(state.entityConfigurationJwt);
    });

    app.post('/wallet-instance-attestation', async (request, reply) => {
      const state = getState();
      const body = request.body as { assertion?: string } | undefined;

      if (!body || typeof body.assertion !== 'string') {
        return sendError(reply, 400, 'bad_request', 'assertion is required');
      }

      if (request.headers['x-test-integrity-fail'] === 'true') {
        return sendError(reply, 403, 'integrity_check_error', 'Device integrity check failed');
      }

      if (request.headers['x-test-validation-error'] === 'true') {
        return sendError(reply, 422, 'validation_error', 'Request failed semantic validation');
      }

      let assertionPayload: Record<string, unknown>;
      let assertionHeader: Record<string, unknown>;
      try {
        assertionHeader = decodeProtectedHeader(body.assertion);
        assertionPayload = decodeJwt(body.assertion) as Record<string, unknown>;
      } catch {
        return sendError(reply, 400, 'bad_request', 'assertion is not a valid JWT');
      }

      if (deviceFailsIntegrityChecks(assertionPayload)) {
        return sendError(
          reply,
          403,
          'integrity_check_error',
          'Wallet instance failed authenticity, integrity, or genuineness checks'
        );
      }

      if (deviceHasKnownSecurityFlaw(assertionPayload)) {
        return sendError(
          reply,
          403,
          'invalid_request',
          'Device does not meet minimum security requirements or has a known security flaw'
        );
      }

      if (assertionHeader.typ !== 'wia-request+jwt') {
        return sendError(reply, 422, 'validation_error', 'assertion typ must be wia-request+jwt');
      }

      const cnf = assertionPayload.cnf as { jwk?: JWK } | undefined;
      if (!cnf?.jwk) {
        return sendError(reply, 400, 'bad_request', 'assertion cnf.jwk is required');
      }

      const thumbprint = await calculateJwkThumbprint(cnf.jwk);
      state.seenEphemeralKeyThumbprints.add(thumbprint);
      recordAttestationIssuance(state, thumbprint);

      const nonce = assertionPayload.nonce;
      if (typeof nonce !== 'string' || !state.nonces.has(nonce)) {
        return sendError(reply, 403, 'invalid_request', 'nonce is invalid, expired, or already used');
      }
      state.nonces.delete(nonce);

      const walletAttestation = await issueWalletAttestationJwt(state, cnf.jwk);
      return reply
        .code(200)
        .header('Content-Type', 'application/json')
        .send({ wallet_attestations: [walletAttestation] });
    });

    app.get('/wallet-instances', async (request, reply) => {
      const token = extractBearerToken(request.headers.authorization);
      if (!token) {
        return sendError(reply, 401, 'unauthorized', 'Missing authentication credentials');
      }

      if (token === 'forbidden-user') {
        return sendError(reply, 403, 'forbidden', 'User is not authorized to retrieve Wallet Instances');
      }

      const instances = [...getState().instances.entries()]
        .filter(([, value]) => value.ownerToken === token)
        .map(([id, value]) => ({
          id,
          issued_at: value.issuedAt,
          status: value.status
        }));

      return reply.code(200).header('Content-Type', 'application/json').send({ wallet_instances: instances });
    });

    app.get('/wallet-instances/:instanceId', async (request, reply) => {
      const token = extractBearerToken(request.headers.authorization);
      if (!token) {
        return sendError(reply, 401, 'unauthorized', 'Missing authentication credentials');
      }

      const { instanceId } = request.params as { instanceId: string };
      const instance = getState().instances.get(instanceId);
      if (!instance) {
        return sendError(reply, 404, 'not_found', 'Wallet instance not found');
      }

      if (instance.ownerToken !== token) {
        return sendError(reply, 403, 'forbidden', 'User is not authorized to retrieve this Wallet Instance');
      }

      return reply.code(200).header('Content-Type', 'application/json').send({
        id: instanceId,
        issued_at: instance.issuedAt,
        status: instance.status
      });
    });

    app.patch('/wallet-instances/:instanceId', async (request, reply) => {
      const token = extractBearerToken(request.headers.authorization);
      if (!token) {
        return sendError(reply, 401, 'unauthorized', 'Missing authentication credentials');
      }

      const body = request.body as { status?: string } | undefined;
      if (!body?.status) {
        return sendError(reply, 400, 'bad_request', 'status is required');
      }

      const { instanceId } = request.params as { instanceId: string };
      const instance = getState().instances.get(instanceId);
      if (!instance) {
        return sendError(reply, 404, 'not_found', 'Wallet instance not found');
      }

      if (instance.ownerToken !== token) {
        return sendError(reply, 403, 'invalid_request', 'User is not authorized to revoke this Wallet Instance');
      }

      if (body.status === 'REVOKED') {
        instance.status = 'REVOKED';
        recordRevocationNotification(getState(), instanceId);
        return reply.code(204).send();
      }

      return sendError(reply, 400, 'bad_request', 'Unsupported status value');
    });
  };
}

export async function buildWalletProviderSimulatorState(
  app: FastifyInstance,
  baseUrl: string
): Promise<WalletProviderSimulatorState> {
  const x5cCertPem = await getX5cCert();
  return {
    baseUrl,
    federationPrivateKeyPem: app.rpKeys.federationPrivateKeyPem,
    x5cCertPem,
    seenEphemeralKeyThumbprints: new Set<string>(),
    nonces: new Map<string, number>(),
    instances: new Map([
      ['wallet-instance-a', { ownerToken: 'user-a', status: 'ACTIVE', issuedAt: new Date().toISOString() }],
      ['wallet-instance-b', { ownerToken: 'user-b', status: 'ACTIVE', issuedAt: new Date().toISOString() }]
    ]),
    federationAccessLog: [],
    attestationIssuanceLog: [],
    revocationNotifications: []
  };
}

export async function buildWiaRequestJwt(input: {
  baseUrl: string;
  nonce: string;
  ephemeralPrivateKey: CryptoKey;
  ephemeralPublicJwk: JWK;
  integrityAssertion?: string;
  hardwareSignature?: string;
  platform?: string;
}): Promise<string> {
  const iss = `${input.baseUrl}/instance/${input.ephemeralPublicJwk.kid}`;
  return new SignJWT({
    cnf: { jwk: input.ephemeralPublicJwk },
    hardware_key_tag: 'test-hardware-key-tag',
    hardware_signature: input.hardwareSignature ?? createHash('sha256').update('client-data-hash').digest('base64url'),
    integrity_assertion: input.integrityAssertion ?? 'test-integrity-assertion',
    nonce: input.nonce,
    platform: input.platform ?? 'test',
    wallet_solution_id: 'itw-conformance-wallet',
    wallet_solution_version: '1.0.0'
  })
    .setProtectedHeader({
      alg: 'ES256',
      kid: input.ephemeralPublicJwk.kid,
      typ: 'wia-request+jwt'
    })
    .setIssuer(iss)
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(input.ephemeralPrivateKey);
}

export async function createEphemeralWalletKeyPair(): Promise<{ privateKey: CryptoKey; publicJwk: JWK }> {
  const { privateKey, publicKey } = await generateKeyPair('ES256');
  const publicJwk = { ...(await exportJWK(publicKey)), alg: 'ES256' };
  publicJwk.kid = await calculateJwkThumbprint(publicJwk);
  return { privateKey, publicJwk };
}

export function containsPiiClaim(value: unknown, path = ''): string[] {
  if (value === null || value === undefined) return [];
  if (Array.isArray(value)) {
    return value.flatMap((item, index) => containsPiiClaim(item, `${path}[${index}]`));
  }
  if (typeof value === 'object') {
    return Object.entries(value as Record<string, unknown>).flatMap(([key, nested]) => {
      const currentPath = path ? `${path}.${key}` : key;
      if (PII_CLAIMS.has(key)) return [currentPath];
      return containsPiiClaim(nested, currentPath);
    });
  }
  return [];
}

export async function verifyWalletAttestationSignature(
  walletAttestationJwt: string,
  federationPublicJwk: JWK
): Promise<boolean> {
  try {
    await jwtVerify(walletAttestationJwt, await importJWK(federationPublicJwk, 'ES256'));
    return true;
  } catch {
    return false;
  }
}
