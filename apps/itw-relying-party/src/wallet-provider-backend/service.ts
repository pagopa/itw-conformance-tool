import { createPrivateKey, createPublicKey, randomUUID } from 'node:crypto';

import { PemConverter, X509Certificate } from '@peculiar/x509';
import { SignJWT, calculateJwkThumbprint, decodeJwt, decodeProtectedHeader, importJWK } from 'jose';

import type { JsonErrorBody, JWK, WalletProviderBackendDeps, WalletProviderBackendState } from './types.js';

const ATTESTATION_TTL_SECONDS = 3600;
const NONCE_TTL_MS = 300_000;

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

export function createWalletProviderBackendState(deps: WalletProviderBackendDeps): WalletProviderBackendState {
  const issuedAt = new Date().toISOString();
  return {
    baseUrl: deps.baseUrl,
    federationPrivateKeyPem: deps.keys.federationPrivateKeyPem,
    x5cCertPem: deps.keys.x5cCertPem,
    seenEphemeralKeyThumbprints: new Set<string>(),
    nonces: new Map<string, number>(),
    instances: new Map([
      ['wallet-instance-a', { ownerToken: 'user-a', status: 'ACTIVE', issuedAt }],
      ['wallet-instance-b', { ownerToken: 'user-b', status: 'ACTIVE', issuedAt }]
    ]),
    federationAccessLog: [],
    attestationIssuanceLog: [],
    revocationNotifications: []
  };
}

export function createJsonError(
  statusCode: number,
  error: string,
  errorDescription: string
): {
  statusCode: number;
  body: JsonErrorBody;
} {
  return {
    statusCode,
    body: { error, error_description: errorDescription }
  };
}

export function extractBearerToken(authorization?: string): string | undefined {
  if (!authorization?.startsWith('Bearer ')) return undefined;
  return authorization.slice('Bearer '.length).trim() || undefined;
}

export function isMaintenanceMode(headers: Record<string, unknown>): boolean {
  return headers['x-test-maintenance'] === 'true';
}

export function isSimulatedServerError(headers: Record<string, unknown>): boolean {
  return headers['x-test-server-error'] === 'true';
}

function recordFederationAccess(state: WalletProviderBackendState, method: string, path: string): void {
  state.federationAccessLog.push({ method, path, timestamp: new Date().toISOString() });
}

function recordAttestationIssuance(state: WalletProviderBackendState, ephemeralKeyThumbprint: string): void {
  state.attestationIssuanceLog.push({
    ephemeralKeyThumbprint,
    timestamp: new Date().toISOString()
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

export async function issueWalletAttestationJwt(
  state: WalletProviderBackendState,
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

export function createNonce(state: WalletProviderBackendState): { nonce: string } {
  const nonce = randomUUID();
  state.nonces.set(nonce, Date.now() + NONCE_TTL_MS);
  return { nonce };
}

export function recordFederationFetchAccess(state: WalletProviderBackendState, method: string, path: string): void {
  recordFederationAccess(state, method, path);
}

type AttestationRequestInput = {
  assertion: string;
  integrityFailHeader?: boolean;
  validationErrorHeader?: boolean;
};

export async function issueWalletAttestationFromRequest(
  state: WalletProviderBackendState,
  input: AttestationRequestInput
): Promise<{ statusCode: number; body: { wallet_instance_attestation: string } | JsonErrorBody }> {
  if (!input.assertion) {
    return createJsonError(400, 'bad_request', 'assertion is required');
  }

  if (input.integrityFailHeader) {
    return createJsonError(403, 'integrity_check_error', 'Device integrity check failed');
  }

  if (input.validationErrorHeader) {
    return createJsonError(422, 'validation_error', 'Request failed semantic validation');
  }

  let assertionPayload: Record<string, unknown>;
  let assertionHeader: Record<string, unknown>;
  try {
    assertionHeader = decodeProtectedHeader(input.assertion);
    assertionPayload = decodeJwt(input.assertion) as Record<string, unknown>;
  } catch {
    return createJsonError(400, 'bad_request', 'assertion is not a valid JWT');
  }

  if (deviceFailsIntegrityChecks(assertionPayload)) {
    return createJsonError(
      403,
      'integrity_check_error',
      'Wallet instance failed authenticity, integrity, or genuineness checks'
    );
  }

  if (deviceHasKnownSecurityFlaw(assertionPayload)) {
    return createJsonError(
      403,
      'invalid_request',
      'Device does not meet minimum security requirements or has a known security flaw'
    );
  }

  if (assertionHeader.typ !== 'wia-request+jwt') {
    return createJsonError(422, 'validation_error', 'assertion typ must be wia-request+jwt');
  }

  const cnf = assertionPayload.cnf as { jwk?: JWK } | undefined;
  if (!cnf?.jwk) {
    return createJsonError(400, 'bad_request', 'assertion cnf.jwk is required');
  }

  const thumbprint = await calculateJwkThumbprint(cnf.jwk);
  state.seenEphemeralKeyThumbprints.add(thumbprint);
  recordAttestationIssuance(state, thumbprint);

  const nonce = assertionPayload.nonce;
  if (typeof nonce !== 'string' || !state.nonces.has(nonce)) {
    return createJsonError(403, 'invalid_request', 'nonce is invalid, expired, or already used');
  }
  state.nonces.delete(nonce);

  const walletAttestation = await issueWalletAttestationJwt(state, cnf.jwk);
  return {
    statusCode: 200,
    body: { wallet_instance_attestation: walletAttestation }
  };
}

export function listWalletInstances(
  state: WalletProviderBackendState,
  token: string | undefined
): { statusCode: number; body: Record<string, unknown> } {
  if (!token) {
    return createJsonError(401, 'unauthorized', 'Missing authentication credentials');
  }

  if (token === 'forbidden-user') {
    return createJsonError(403, 'forbidden', 'User is not authorized to retrieve Wallet Instances');
  }

  const walletInstances = [...state.instances.entries()]
    .filter(([, value]) => value.ownerToken === token)
    .map(([id, value]) => ({
      id,
      issued_at: value.issuedAt,
      status: value.status
    }));

  return { statusCode: 200, body: { wallet_instances: walletInstances } };
}

export function getWalletInstance(
  state: WalletProviderBackendState,
  instanceId: string,
  token: string | undefined
): { statusCode: number; body: Record<string, unknown> } {
  if (!token) {
    return createJsonError(401, 'unauthorized', 'Missing authentication credentials');
  }

  const instance = state.instances.get(instanceId);
  if (!instance) {
    return createJsonError(404, 'not_found', 'Wallet instance not found');
  }

  if (instance.ownerToken !== token) {
    return createJsonError(403, 'forbidden', 'User is not authorized to retrieve this Wallet Instance');
  }

  return {
    statusCode: 200,
    body: {
      id: instanceId,
      issued_at: instance.issuedAt,
      status: instance.status,
      revoked_at: instance.revokedAt,
      notified_at: instance.notifiedAt
    }
  };
}

export function revokeWalletInstance(
  state: WalletProviderBackendState,
  instanceId: string,
  token: string | undefined,
  status: string | undefined
): { statusCode: number; body?: JsonErrorBody } {
  if (!token) {
    return createJsonError(401, 'unauthorized', 'Missing authentication credentials');
  }

  if (!status) {
    return createJsonError(400, 'bad_request', 'status is required');
  }

  const instance = state.instances.get(instanceId);
  if (!instance) {
    return createJsonError(404, 'not_found', 'Wallet instance not found');
  }

  if (instance.ownerToken !== token) {
    return createJsonError(403, 'invalid_request', 'User is not authorized to revoke this Wallet Instance');
  }

  if (status !== 'REVOKED') {
    return createJsonError(400, 'bad_request', 'Unsupported status value');
  }

  const revokedAt = new Date().toISOString();
  const notifiedAt = new Date().toISOString();
  instance.status = 'REVOKED';
  instance.revokedAt = revokedAt;
  instance.notifiedAt = notifiedAt;
  state.revocationNotifications.push({ instanceId, revokedAt, notifiedAt });

  return { statusCode: 204 };
}

export function getConformanceDebugSnapshot(state: WalletProviderBackendState): Record<string, unknown> {
  return {
    federation_access_log: state.federationAccessLog,
    attestation_issuance_log: state.attestationIssuanceLog,
    revocation_notifications: state.revocationNotifications
  };
}
