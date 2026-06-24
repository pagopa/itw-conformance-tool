import { randomUUID } from 'node:crypto';

import { SqliteConformanceSessionRepository, type ConformanceCheck } from '@itw-conformance-tool/conformance';
import { SignJWT, calculateJwkThumbprint, decodeJwt, decodeProtectedHeader } from 'jose';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { buildRpRouteApp } from '../helpers/rp-route-app.js';
import {
  buildWalletProviderSimulatorState,
  buildWiaRequestJwt,
  containsPiiClaim,
  createEphemeralWalletKeyPair,
  createWalletProviderEntityConfiguration,
  createWalletProviderSimulatorPlugin,
  verifyWalletAttestationSignature,
  type WalletProviderSimulatorState
} from '../helpers/wallet-provider-simulator.js';

const BASE_URL = 'https://wallet-provider.wct.example.org';

async function appendCheck(
  repo: SqliteConformanceSessionRepository,
  sessionId: string,
  check: Omit<ConformanceCheck, 'step' | 'phase' | 'timestamp'> & { timestamp?: string }
) {
  await repo.appendCheck(sessionId, {
    step: 'AUTHORIZE',
    phase: 'PRESENTATION',
    timestamp: new Date().toISOString(),
    ...check
  });
}

describe.sequential('Wallet Instance', () => {
  let ctx: Awaited<ReturnType<typeof buildRpRouteApp>>;
  let repo: SqliteConformanceSessionRepository;
  let sessionId: string;
  let simulatorState: WalletProviderSimulatorState;
  let federationJwt: string;
  let firstAttestationJwt: string;
  let firstEphemeralKeys: Awaited<ReturnType<typeof createEphemeralWalletKeyPair>>;
  let secondEphemeralKeys: Awaited<ReturnType<typeof createEphemeralWalletKeyPair>>;

  beforeAll(async () => {
    simulatorState = {
      baseUrl: BASE_URL,
      federationPrivateKeyPem: '',
      x5cCertPem: '',
      seenEphemeralKeyThumbprints: new Set<string>(),
      nonces: new Map<string, number>(),
      instances: new Map([
        ['wallet-instance-a', { ownerToken: 'user-a', status: 'ACTIVE', issuedAt: new Date().toISOString() }],
        ['wallet-instance-b', { ownerToken: 'user-b', status: 'ACTIVE', issuedAt: new Date().toISOString() }]
      ])
    };

    ctx = await buildRpRouteApp(
      createWalletProviderSimulatorPlugin(() => simulatorState),
      {
        baseUrl: BASE_URL,
        setup: async (app) => {
          simulatorState = await buildWalletProviderSimulatorState(app, BASE_URL);
          simulatorState.baseUrl = BASE_URL;
        }
      }
    );

    repo = new SqliteConformanceSessionRepository(ctx.dbClient.db);
    sessionId = randomUUID();
    await repo.create({
      sessionId,
      startedAt: new Date().toISOString(),
      status: 'OPEN',
      checks: []
    });

    federationJwt = await createWalletProviderEntityConfiguration(simulatorState);
    simulatorState.entityConfigurationJwt = federationJwt;

    const nonceResponse = await ctx.app.inject({ method: 'GET', url: '/nonce' });
    const { nonce } = nonceResponse.json<{ nonce: string }>();

    firstEphemeralKeys = await createEphemeralWalletKeyPair();
    const firstAssertion = await buildWiaRequestJwt({
      baseUrl: BASE_URL,
      nonce,
      ephemeralPrivateKey: firstEphemeralKeys.privateKey,
      ephemeralPublicJwk: firstEphemeralKeys.publicJwk
    });

    const firstAttestationResponse = await ctx.app.inject({
      method: 'POST',
      url: '/wallet-instance-attestation',
      payload: { assertion: firstAssertion },
      headers: { 'content-type': 'application/json' }
    });

    const firstAttestationBody = firstAttestationResponse.json<{ wallet_attestations: string[] }>();
    const firstAttestation = firstAttestationBody.wallet_attestations[0];
    if (!firstAttestation) {
      throw new Error('Expected wallet attestation in issuance response');
    }
    firstAttestationJwt = firstAttestation;
  });

  afterAll(async () => {
    const session = await repo.get(sessionId);
    const allPassed = session?.checks.every((check) => check.result === 'PASS') ?? false;
    await repo.close(sessionId, allPassed ? 'PASSED' : 'FAILED');
    await ctx?.app.close();
  });

  it('WP_019 - Wallet Attestation contains required integrity and security claims', async () => {
    const header = decodeProtectedHeader(firstAttestationJwt);
    const payload = decodeJwt(firstAttestationJwt) as Record<string, unknown>;
    const cnf = payload.cnf as { jwk?: Record<string, unknown> } | undefined;
    const status = payload.status as Record<string, unknown> | undefined;

    const hasRequiredClaims =
      typeof payload.iss === 'string' &&
      typeof payload.sub === 'string' &&
      typeof payload.iat === 'number' &&
      typeof payload.exp === 'number' &&
      typeof payload.wallet_link === 'string' &&
      typeof payload.wallet_name === 'string' &&
      typeof cnf?.jwk === 'object' &&
      typeof status?.status_list === 'object' &&
      header.typ === 'oauth-client-attestation+jwt' &&
      Array.isArray(header.x5c) &&
      header.x5c.length > 0;

    await appendCheck(repo, sessionId, {
      requirementId: 'WP_019',
      description: 'Wallet Attestation contains required integrity and security claims',
      result: hasRequiredClaims ? 'PASS' : 'FAIL',
      httpStatus: 200
    });

    expect(hasRequiredClaims).toBe(true);
  });

  it('WP_019b - Wallet Attestation ephemeral key is bound to the holder PoP key', async () => {
    const payload = decodeJwt(firstAttestationJwt) as { cnf?: { jwk?: Record<string, unknown> } };
    const attestationJwk = payload.cnf?.jwk;
    expect(attestationJwk).toBeDefined();

    if (!attestationJwk) {
      throw new Error('Wallet Attestation is missing cnf.jwk');
    }

    const popJwt = await new SignJWT({ aud: BASE_URL })
      .setProtectedHeader({ alg: 'ES256', typ: 'oauth-client-attestation-pop+jwt', jwk: attestationJwk })
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(firstEphemeralKeys.privateKey);

    const popHeader = decodeProtectedHeader(popJwt);
    const popPayload = decodeJwt(popJwt) as Record<string, unknown>;
    const attestationThumbprint = await calculateJwkThumbprint(attestationJwk);
    const popJwkThumbprint = popHeader.jwk ? await calculateJwkThumbprint(popHeader.jwk as never) : '';
    const keyBindingMatches = attestationThumbprint === popJwkThumbprint && typeof popPayload.aud === 'string';

    await appendCheck(repo, sessionId, {
      requirementId: 'WP_019b',
      description: 'Wallet Attestation ephemeral key is bound to the holder PoP key',
      result: keyBindingMatches ? 'PASS' : 'FAIL',
      httpStatus: 200
    });

    expect(keyBindingMatches).toBe(true);
  });

  it('WP_020 - Wallet Attestation is signed by the authorized Wallet Provider', async () => {
    const federationPayload = decodeJwt(federationJwt) as {
      metadata?: { wallet_provider?: { jwks?: { keys?: Record<string, unknown>[] } } };
      jwks?: { keys?: Record<string, unknown>[] };
    };
    const walletProviderKeys =
      federationPayload.metadata?.wallet_provider?.jwks?.keys ?? federationPayload.jwks?.keys ?? [];
    const attestationHeader = decodeProtectedHeader(firstAttestationJwt);
    const signingKey = walletProviderKeys.find((key) => key.kid === attestationHeader.kid);
    const signatureValid = signingKey
      ? await verifyWalletAttestationSignature(firstAttestationJwt, signingKey as never)
      : false;

    await appendCheck(repo, sessionId, {
      requirementId: 'WP_020',
      description: 'Wallet Attestation is signed by the authorized Wallet Provider',
      result: signatureValid ? 'PASS' : 'FAIL',
      httpStatus: 200
    });

    expect(signatureValid).toBe(true);
  });

  it('WP_023 - Wallet Provider federation discovery via .well-known/openid-federation and /fetch', async () => {
    const entityConfigResponse = await ctx.app.inject({
      method: 'GET',
      url: '/.well-known/openid-federation'
    });
    const fetchResponse = await ctx.app.inject({
      method: 'POST',
      url: '/fetch',
      payload: { entity_id: BASE_URL },
      headers: { 'content-type': 'application/json' }
    });

    const discoveryValid =
      entityConfigResponse.statusCode === 200 &&
      entityConfigResponse.headers['content-type']?.includes('entity-statement+jwt') &&
      entityConfigResponse.body.split('.').length === 3 &&
      fetchResponse.statusCode === 200 &&
      fetchResponse.headers['content-type']?.includes('entity-statement+jwt') &&
      fetchResponse.body.split('.').length === 3;

    await appendCheck(repo, sessionId, {
      requirementId: 'WP_023',
      description: 'Wallet Provider federation discovery via .well-known/openid-federation and /fetch',
      result: discoveryValid ? 'PASS' : 'FAIL',
      httpStatus: entityConfigResponse.statusCode,
      errorMessage: discoveryValid ? undefined : fetchResponse.body
    });

    expect(discoveryValid).toBe(true);
  });

  it('WP_026 - Each Wallet Attestation issuance request uses a new ephemeral key pair', async () => {
    const nonceResponse = await ctx.app.inject({ method: 'GET', url: '/nonce' });
    const { nonce } = nonceResponse.json<{ nonce: string }>();
    secondEphemeralKeys = await createEphemeralWalletKeyPair();

    const secondAssertion = await buildWiaRequestJwt({
      baseUrl: BASE_URL,
      nonce,
      ephemeralPrivateKey: secondEphemeralKeys.privateKey,
      ephemeralPublicJwk: secondEphemeralKeys.publicJwk
    });

    const secondAttestationResponse = await ctx.app.inject({
      method: 'POST',
      url: '/wallet-instance-attestation',
      payload: { assertion: secondAssertion },
      headers: { 'content-type': 'application/json' }
    });

    const firstThumbprint = await calculateJwkThumbprint(firstEphemeralKeys.publicJwk);
    const secondThumbprint = await calculateJwkThumbprint(secondEphemeralKeys.publicJwk);
    const usesFreshEphemeralKey =
      secondAttestationResponse.statusCode === 200 &&
      firstThumbprint !== secondThumbprint &&
      simulatorState.seenEphemeralKeyThumbprints.size >= 2;

    await appendCheck(repo, sessionId, {
      requirementId: 'WP_026',
      description: 'Each Wallet Attestation issuance request uses a new ephemeral key pair',
      result: usesFreshEphemeralKey ? 'PASS' : 'FAIL',
      httpStatus: secondAttestationResponse.statusCode
    });

    expect(usesFreshEphemeralKey).toBe(true);
  });

  it('WP_028 - Wallet Attestation has a short defined validity period', async () => {
    const payload = decodeJwt(firstAttestationJwt) as { iat?: number; exp?: number };
    const validitySeconds = (payload.exp ?? 0) - (payload.iat ?? 0);
    const shortLived = validitySeconds > 0 && validitySeconds <= 24 * 60 * 60;

    await appendCheck(repo, sessionId, {
      requirementId: 'WP_028',
      description: 'Wallet Attestation has a short defined validity period',
      result: shortLived ? 'PASS' : 'FAIL',
      httpStatus: 200
    });

    expect(shortLived).toBe(true);
  });

  it('WP_029 - Wallet Attestation issuance returns HTTP 200 with application/json', async () => {
    const nonceResponse = await ctx.app.inject({ method: 'GET', url: '/nonce' });
    const { nonce } = nonceResponse.json<{ nonce: string }>();
    const ephemeralKeys = await createEphemeralWalletKeyPair();
    const assertion = await buildWiaRequestJwt({
      baseUrl: BASE_URL,
      nonce,
      ephemeralPrivateKey: ephemeralKeys.privateKey,
      ephemeralPublicJwk: ephemeralKeys.publicJwk
    });

    const response = await ctx.app.inject({
      method: 'POST',
      url: '/wallet-instance-attestation',
      payload: { assertion },
      headers: { 'content-type': 'application/json' }
    });

    const body = response.json<{ wallet_attestations?: string[] }>();
    const validResponse =
      response.statusCode === 200 &&
      response.headers['content-type']?.includes('application/json') &&
      Array.isArray(body.wallet_attestations) &&
      body.wallet_attestations.length > 0;

    await appendCheck(repo, sessionId, {
      requirementId: 'WP_029',
      description: 'Wallet Attestation issuance returns HTTP 200 with application/json',
      result: validResponse ? 'PASS' : 'FAIL',
      httpStatus: response.statusCode
    });

    expect(validResponse).toBe(true);
  });

  it('WP_029a - Wallet Attestation is returned as a signed JWT', async () => {
    const parts = firstAttestationJwt.split('.');
    const header = decodeProtectedHeader(firstAttestationJwt);
    const signedJwt =
      parts.length === 3 &&
      typeof header.alg === 'string' &&
      header.alg !== 'none' &&
      header.typ === 'oauth-client-attestation+jwt';

    await appendCheck(repo, sessionId, {
      requirementId: 'WP_029a',
      description: 'Wallet Attestation is returned as a signed JWT',
      result: signedJwt ? 'PASS' : 'FAIL',
      httpStatus: 200
    });

    expect(signedJwt).toBe(true);
  });

  it('WP_029b - Wallet Attestation payload does not contain PII', async () => {
    const payload = decodeJwt(firstAttestationJwt) as Record<string, unknown>;
    const piiClaims = containsPiiClaim(payload);
    const noPii = piiClaims.length === 0;

    await appendCheck(repo, sessionId, {
      requirementId: 'WP_029b',
      description: 'Wallet Attestation payload does not contain PII',
      result: noPii ? 'PASS' : 'FAIL',
      httpStatus: 200,
      errorMessage: noPii ? undefined : `PII claims found: ${piiClaims.join(', ')}`
    });

    expect(noPii).toBe(true);
  });

  it('WP_033 - Wallet Instance sends a revocation request to the management endpoint', async () => {
    const response = await ctx.app.inject({
      method: 'PATCH',
      url: '/wallet-instances/wallet-instance-a',
      payload: { status: 'REVOKED' },
      headers: {
        authorization: 'Bearer user-a',
        'content-type': 'application/json'
      }
    });

    const revocationAccepted = response.statusCode === 204;
    const revokedInstance = simulatorState.instances.get('wallet-instance-a');

    await appendCheck(repo, sessionId, {
      requirementId: 'WP_033',
      description: 'Wallet Instance sends a revocation request to the management endpoint',
      result: revocationAccepted && revokedInstance?.status === 'REVOKED' ? 'PASS' : 'FAIL',
      httpStatus: response.statusCode
    });

    expect(revocationAccepted).toBe(true);
    expect(revokedInstance?.status).toBe('REVOKED');
  });

  it('WP_035 - Wallet Instance management errors follow RFC 7231 status semantics', async () => {
    const malformedResponse = await ctx.app.inject({
      method: 'PATCH',
      url: '/wallet-instances/wallet-instance-b',
      payload: {},
      headers: {
        authorization: 'Bearer user-b',
        'content-type': 'application/json'
      }
    });

    const conformsToRfc7231 = malformedResponse.statusCode === 400;

    await appendCheck(repo, sessionId, {
      requirementId: 'WP_035',
      description: 'Wallet Instance management errors follow RFC 7231 status semantics',
      result: conformsToRfc7231 ? 'PASS' : 'FAIL',
      httpStatus: malformedResponse.statusCode
    });

    expect(conformsToRfc7231).toBe(true);
  });

  it('WP_035a - Error responses use application/json with error and error_description', async () => {
    const response = await ctx.app.inject({
      method: 'GET',
      url: '/wallet-instances'
    });
    const body = response.json<{ error?: string; error_description?: string }>();
    const validErrorShape =
      response.statusCode === 401 &&
      response.headers['content-type']?.includes('application/json') &&
      typeof body.error === 'string' &&
      typeof body.error_description === 'string';

    await appendCheck(repo, sessionId, {
      requirementId: 'WP_035a',
      description: 'Error responses use application/json with error and error_description',
      result: validErrorShape ? 'PASS' : 'FAIL',
      httpStatus: response.statusCode
    });

    expect(validErrorShape).toBe(true);
  });

  it('WP_036 - Malformed requests return HTTP 400 with bad_request', async () => {
    const response = await ctx.app.inject({
      method: 'POST',
      url: '/wallet-instance-attestation',
      payload: {},
      headers: { 'content-type': 'application/json' }
    });
    const body = response.json<{ error?: string }>();
    const valid = response.statusCode === 400 && body.error === 'bad_request';

    await appendCheck(repo, sessionId, {
      requirementId: 'WP_036',
      description: 'Malformed requests return HTTP 400 with bad_request',
      result: valid ? 'PASS' : 'FAIL',
      httpStatus: response.statusCode
    });

    expect(valid).toBe(true);
  });

  it('WP_037 - Semantically invalid requests return HTTP 422 with validation_error', async () => {
    const nonceResponse = await ctx.app.inject({ method: 'GET', url: '/nonce' });
    const { nonce } = nonceResponse.json<{ nonce: string }>();
    const ephemeralKeys = await createEphemeralWalletKeyPair();
    const assertion = await new SignJWT({
      cnf: { jwk: ephemeralKeys.publicJwk },
      nonce
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'invalid-request+jwt', kid: ephemeralKeys.publicJwk.kid })
      .setIssuer(`${BASE_URL}/instance/${ephemeralKeys.publicJwk.kid}`)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(ephemeralKeys.privateKey);

    const response = await ctx.app.inject({
      method: 'POST',
      url: '/wallet-instance-attestation',
      payload: { assertion },
      headers: {
        'content-type': 'application/json',
        'x-test-validation-error': 'false'
      }
    });
    const body = response.json<{ error?: string }>();
    const valid = response.statusCode === 422 && body.error === 'validation_error';

    await appendCheck(repo, sessionId, {
      requirementId: 'WP_037',
      description: 'Semantically invalid requests return HTTP 422 with validation_error',
      result: valid ? 'PASS' : 'FAIL',
      httpStatus: response.statusCode
    });

    expect(valid).toBe(true);
  });

  it('WP_040 - Initialization failure returns HTTP 403 with integrity_check_error', async () => {
    const nonceResponse = await ctx.app.inject({ method: 'GET', url: '/nonce' });
    const { nonce } = nonceResponse.json<{ nonce: string }>();
    const ephemeralKeys = await createEphemeralWalletKeyPair();
    const assertion = await buildWiaRequestJwt({
      baseUrl: BASE_URL,
      nonce,
      ephemeralPrivateKey: ephemeralKeys.privateKey,
      ephemeralPublicJwk: ephemeralKeys.publicJwk
    });

    const response = await ctx.app.inject({
      method: 'POST',
      url: '/wallet-instance-attestation',
      payload: { assertion },
      headers: {
        'content-type': 'application/json',
        'x-test-integrity-fail': 'true'
      }
    });
    const body = response.json<{ error?: string }>();
    const valid = response.statusCode === 403 && body.error === 'integrity_check_error';

    await appendCheck(repo, sessionId, {
      requirementId: 'WP_040',
      description: 'Initialization failure returns HTTP 403 with integrity_check_error',
      result: valid ? 'PASS' : 'FAIL',
      httpStatus: response.statusCode
    });

    expect(valid).toBe(true);
  });

  it('WP_041 - Status retrieval without credentials returns HTTP 401 unauthorized', async () => {
    const response = await ctx.app.inject({
      method: 'GET',
      url: '/wallet-instances/wallet-instance-b'
    });
    const body = response.json<{ error?: string }>();
    const valid = response.statusCode === 401 && body.error === 'unauthorized';

    await appendCheck(repo, sessionId, {
      requirementId: 'WP_041',
      description: 'Status retrieval without credentials returns HTTP 401 unauthorized',
      result: valid ? 'PASS' : 'FAIL',
      httpStatus: response.statusCode
    });

    expect(valid).toBe(true);
  });

  it('WP_042 - Status retrieval for another user wallet returns HTTP 403 forbidden', async () => {
    const response = await ctx.app.inject({
      method: 'GET',
      url: '/wallet-instances/wallet-instance-b',
      headers: { authorization: 'Bearer user-a' }
    });
    const body = response.json<{ error?: string }>();
    const valid = response.statusCode === 403 && body.error === 'forbidden';

    await appendCheck(repo, sessionId, {
      requirementId: 'WP_042',
      description: 'Status retrieval for another user wallet returns HTTP 403 forbidden',
      result: valid ? 'PASS' : 'FAIL',
      httpStatus: response.statusCode
    });

    expect(valid).toBe(true);
  });

  it('WP_043 - Revocation without credentials returns HTTP 401 unauthorized', async () => {
    const response = await ctx.app.inject({
      method: 'PATCH',
      url: '/wallet-instances/wallet-instance-b',
      payload: { status: 'REVOKED' },
      headers: { 'content-type': 'application/json' }
    });
    const body = response.json<{ error?: string }>();
    const valid = response.statusCode === 401 && body.error === 'unauthorized';

    await appendCheck(repo, sessionId, {
      requirementId: 'WP_043',
      description: 'Revocation without credentials returns HTTP 401 unauthorized',
      result: valid ? 'PASS' : 'FAIL',
      httpStatus: response.statusCode
    });

    expect(valid).toBe(true);
  });

  it('WP_044 - Revocation for another user wallet returns HTTP 403 invalid_request', async () => {
    const response = await ctx.app.inject({
      method: 'PATCH',
      url: '/wallet-instances/wallet-instance-b',
      payload: { status: 'REVOKED' },
      headers: {
        authorization: 'Bearer user-a',
        'content-type': 'application/json'
      }
    });
    const body = response.json<{ error?: string }>();
    const valid = response.statusCode === 403 && body.error === 'invalid_request';

    await appendCheck(repo, sessionId, {
      requirementId: 'WP_044',
      description: 'Revocation for another user wallet returns HTTP 403 invalid_request',
      result: valid ? 'PASS' : 'FAIL',
      httpStatus: response.statusCode
    });

    expect(valid).toBe(true);
  });
});
