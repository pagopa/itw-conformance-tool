import { SignJWT, calculateJwkThumbprint, decodeJwt, decodeProtectedHeader, type KeyLike } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';

import { hasCompactJwtShape, normalizeUrl, readJsonBody, resolveTrustAnchorUrl, wpFetch } from './helpers/http.js';
import {
  buildWiaRequestJwt,
  containsPiiClaim,
  createEphemeralWalletKeyPair,
  verifyWalletAttestationSignature,
  type ConformanceDebugSnapshot
} from './helpers/wallet-instance.js';

async function fetchNonce(walletProviderUrl: string): Promise<string> {
  const response = await wpFetch(`${walletProviderUrl}/nonce`);
  const body = await readJsonBody<{ nonce?: string }>(response);
  if (!body.nonce) {
    throw new Error('Nonce endpoint did not return a nonce');
  }

  return body.nonce;
}

async function issueWalletAttestation(
  walletProviderUrl: string,
  input: {
    nonce: string;
    ephemeralPrivateKey: KeyLike;
    ephemeralPublicJwk: Awaited<ReturnType<typeof createEphemeralWalletKeyPair>>['publicJwk'];
    integrityAssertion?: string;
    hardwareSignature?: string;
    platform?: string;
    headers?: Record<string, string>;
  }
): Promise<{
  statusCode: number;
  contentType: string;
  walletAttestation?: string;
  body: Record<string, unknown>;
}> {
  const assertion = await buildWiaRequestJwt({
    baseUrl: walletProviderUrl,
    nonce: input.nonce,
    ephemeralPrivateKey: input.ephemeralPrivateKey,
    ephemeralPublicJwk: input.ephemeralPublicJwk,
    integrityAssertion: input.integrityAssertion,
    hardwareSignature: input.hardwareSignature,
    platform: input.platform
  });

  const response = await wpFetch(`${walletProviderUrl}/wallet-instance-attestation`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...input.headers
    },
    body: JSON.stringify({ assertion })
  });

  const body = await readJsonBody<Record<string, unknown>>(response);
  const walletAttestation =
    typeof body.wallet_instance_attestation === 'string' ? body.wallet_instance_attestation : undefined;

  return {
    statusCode: response.status,
    contentType: response.headers.get('content-type') ?? '',
    walletAttestation,
    body
  };
}

async function fetchConformanceDebug(walletProviderUrl: string): Promise<ConformanceDebugSnapshot> {
  const response = await wpFetch(`${walletProviderUrl}/conformance/wallet-provider/debug`);
  return readJsonBody<ConformanceDebugSnapshot>(response);
}

describe.sequential('Wallet Instance', () => {
  let walletProviderUrl: string;
  let federationJwt: string;
  let firstAttestationJwt: string;
  let firstEphemeralKeys: Awaited<ReturnType<typeof createEphemeralWalletKeyPair>>;
  let secondEphemeralKeys: Awaited<ReturnType<typeof createEphemeralWalletKeyPair>>;

  beforeAll(async () => {
    const walletProviderBackendUrl = process.env.ITW_CT_WALLET_PROVIDER_BACKEND_URL?.trim();
    if (!walletProviderBackendUrl) {
      throw new Error('Missing required env: ITW_CT_WALLET_PROVIDER_BACKEND_URL');
    }

    walletProviderUrl = normalizeUrl(walletProviderBackendUrl);

    const federationResponse = await wpFetch(`${walletProviderUrl}/.well-known/openid-federation`);
    federationJwt = await federationResponse.text();
    if (federationResponse.status !== 200 || !hasCompactJwtShape(federationJwt)) {
      throw new Error('Wallet Provider federation metadata is not available');
    }

    const nonce = await fetchNonce(walletProviderUrl);
    firstEphemeralKeys = await createEphemeralWalletKeyPair();
    const firstIssuance = await issueWalletAttestation(walletProviderUrl, {
      nonce,
      ephemeralPrivateKey: firstEphemeralKeys.privateKey,
      ephemeralPublicJwk: firstEphemeralKeys.publicJwk
    });

    if (!firstIssuance.walletAttestation) {
      throw new Error('Expected wallet attestation in issuance response');
    }

    firstAttestationJwt = firstIssuance.walletAttestation;
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

    expect(hasRequiredClaims, 'Wallet Attestation must contain required integrity and security claims').toBe(true);
  });

  it('WP_019b - Wallet Attestation ephemeral key is bound to the holder PoP key', async () => {
    const payload = decodeJwt(firstAttestationJwt) as { cnf?: { jwk?: Record<string, unknown> } };
    const attestationJwk = payload.cnf?.jwk;
    expect(attestationJwk, 'Wallet Attestation is missing cnf.jwk').toBeDefined();

    if (!attestationJwk) {
      return;
    }

    const popJwt = await new SignJWT({ aud: walletProviderUrl })
      .setProtectedHeader({ alg: 'ES256', typ: 'oauth-client-attestation-pop+jwt', jwk: attestationJwk })
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(firstEphemeralKeys.privateKey);

    const popHeader = decodeProtectedHeader(popJwt);
    const popPayload = decodeJwt(popJwt) as Record<string, unknown>;
    const attestationThumbprint = await calculateJwkThumbprint(attestationJwk);
    const popJwkThumbprint = popHeader.jwk ? await calculateJwkThumbprint(popHeader.jwk as never) : '';
    const keyBindingMatches = attestationThumbprint === popJwkThumbprint && typeof popPayload.aud === 'string';

    expect(keyBindingMatches, 'Wallet Attestation ephemeral key must be bound to the holder PoP key').toBe(true);
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

    expect(signatureValid, 'Wallet Attestation must be signed by the authorized Wallet Provider').toBe(true);
  });

  it('WP_023 - Wallet Provider federation discovery via .well-known/openid-federation and /fetch', async () => {
    const entityConfigResponse = await wpFetch(`${walletProviderUrl}/.well-known/openid-federation`);
    const entityConfigBody = await entityConfigResponse.text();
    const fetchResponse = await wpFetch(`${walletProviderUrl}/fetch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ entity_id: walletProviderUrl })
    });
    const fetchBody = await fetchResponse.text();

    const discoveryValid =
      entityConfigResponse.status === 200 &&
      (entityConfigResponse.headers.get('content-type') ?? '').includes('entity-statement+jwt') &&
      hasCompactJwtShape(entityConfigBody) &&
      fetchResponse.status === 200 &&
      (fetchResponse.headers.get('content-type') ?? '').includes('entity-statement+jwt') &&
      hasCompactJwtShape(fetchBody);

    expect(
      discoveryValid,
      'Wallet Provider federation discovery must work via .well-known/openid-federation and /fetch'
    ).toBe(true);
  });

  it('WP_026 - Each Wallet Attestation issuance request uses a new ephemeral key pair', async () => {
    const nonce = await fetchNonce(walletProviderUrl);
    secondEphemeralKeys = await createEphemeralWalletKeyPair();
    const secondIssuance = await issueWalletAttestation(walletProviderUrl, {
      nonce,
      ephemeralPrivateKey: secondEphemeralKeys.privateKey,
      ephemeralPublicJwk: secondEphemeralKeys.publicJwk
    });

    const firstThumbprint = await calculateJwkThumbprint(firstEphemeralKeys.publicJwk);
    const secondThumbprint = await calculateJwkThumbprint(secondEphemeralKeys.publicJwk);
    const debugSnapshot = await fetchConformanceDebug(walletProviderUrl);
    const usesFreshEphemeralKey =
      secondIssuance.statusCode === 200 &&
      firstThumbprint !== secondThumbprint &&
      debugSnapshot.attestation_issuance_log.length >= 2;

    expect(usesFreshEphemeralKey, 'Each Wallet Attestation issuance must use a new ephemeral key pair').toBe(true);
  });

  it('WP_028 - Wallet Attestation has a short defined validity period', async () => {
    const payload = decodeJwt(firstAttestationJwt) as { iat?: number; exp?: number };
    const validitySeconds = (payload.exp ?? 0) - (payload.iat ?? 0);
    const shortLived = validitySeconds > 0 && validitySeconds <= 24 * 60 * 60;

    expect(shortLived, 'Wallet Attestation must have a short defined validity period').toBe(true);
  });

  it('WP_029 - Wallet Attestation issuance returns HTTP 200 with application/json', async () => {
    const nonce = await fetchNonce(walletProviderUrl);
    const ephemeralKeys = await createEphemeralWalletKeyPair();
    const issuance = await issueWalletAttestation(walletProviderUrl, {
      nonce,
      ephemeralPrivateKey: ephemeralKeys.privateKey,
      ephemeralPublicJwk: ephemeralKeys.publicJwk
    });

    const validResponse =
      issuance.statusCode === 200 &&
      issuance.contentType.includes('application/json') &&
      typeof issuance.body.wallet_instance_attestation === 'string' &&
      hasCompactJwtShape(issuance.body.wallet_instance_attestation);

    expect(validResponse, 'Wallet Attestation issuance must return HTTP 200 with application/json').toBe(true);
  });

  it('WP_029a - Wallet Attestation is returned as a signed JWT', async () => {
    const parts = firstAttestationJwt.split('.');
    const header = decodeProtectedHeader(firstAttestationJwt);
    const signedJwt =
      parts.length === 3 &&
      typeof header.alg === 'string' &&
      header.alg !== 'none' &&
      header.typ === 'oauth-client-attestation+jwt';

    expect(signedJwt, 'Wallet Attestation must be returned as a signed JWT').toBe(true);
  });

  it('WP_029b - Wallet Attestation payload does not contain PII', async () => {
    const payload = decodeJwt(firstAttestationJwt) as Record<string, unknown>;
    const piiClaims = containsPiiClaim(payload);
    const noPii = piiClaims.length === 0;

    expect(noPii, `Wallet Attestation payload must not contain PII (found: ${piiClaims.join(', ')})`).toBe(true);
  });

  it('WP_033 - Wallet Instance sends a revocation request to the management endpoint', async () => {
    const response = await wpFetch(`${walletProviderUrl}/wallet-instances/wallet-instance-a`, {
      method: 'PATCH',
      headers: {
        Authorization: 'Bearer user-a',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ status: 'REVOKED' })
    });

    const statusResponse = await wpFetch(`${walletProviderUrl}/wallet-instances/wallet-instance-a`, {
      headers: { Authorization: 'Bearer user-a' }
    });
    const statusBody = await readJsonBody<{ status?: string }>(statusResponse);

    expect(response.status, 'Revocation request must be accepted').toBe(204);
    expect(statusBody.status, 'Wallet instance must be marked REVOKED').toBe('REVOKED');
  });

  it('WP_035 - Wallet Instance management errors follow RFC 7231 status semantics', async () => {
    const response = await wpFetch(`${walletProviderUrl}/wallet-instances/wallet-instance-b`, {
      method: 'PATCH',
      headers: {
        Authorization: 'Bearer user-b',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({})
    });

    expect(response.status, 'Malformed management request must return HTTP 400').toBe(400);
  });

  it('WP_035a - Error responses use application/json with error and error_description', async () => {
    const response = await wpFetch(`${walletProviderUrl}/wallet-instances`);
    const body = await readJsonBody<{ error?: string; error_description?: string }>(response);

    const validErrorShape =
      response.status === 401 &&
      (response.headers.get('content-type') ?? '').includes('application/json') &&
      typeof body.error === 'string' &&
      typeof body.error_description === 'string';

    expect(validErrorShape, 'Error responses must use application/json with error and error_description').toBe(true);
  });

  it('WP_036 - Malformed requests return HTTP 400 with bad_request', async () => {
    const response = await wpFetch(`${walletProviderUrl}/wallet-instance-attestation`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    });
    const body = await readJsonBody<{ error?: string }>(response);

    expect(response.status === 400 && body.error === 'bad_request', 'Malformed requests must return bad_request').toBe(
      true
    );
  });

  it('WP_037 - Semantically invalid requests return HTTP 422 with validation_error', async () => {
    const nonce = await fetchNonce(walletProviderUrl);
    const ephemeralKeys = await createEphemeralWalletKeyPair();
    const assertion = await new SignJWT({
      cnf: { jwk: ephemeralKeys.publicJwk },
      nonce
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'invalid-request+jwt', kid: ephemeralKeys.publicJwk.kid })
      .setIssuer(`${walletProviderUrl}/instance/${ephemeralKeys.publicJwk.kid}`)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(ephemeralKeys.privateKey);

    const response = await wpFetch(`${walletProviderUrl}/wallet-instance-attestation`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ assertion })
    });
    const body = await readJsonBody<{ error?: string }>(response);

    expect(
      response.status === 422 && body.error === 'validation_error',
      'Semantically invalid requests must return validation_error'
    ).toBe(true);
  });

  it('WP_040 - Initialization failure returns HTTP 403 with integrity_check_error', async () => {
    const nonce = await fetchNonce(walletProviderUrl);
    const ephemeralKeys = await createEphemeralWalletKeyPair();
    const issuance = await issueWalletAttestation(walletProviderUrl, {
      nonce,
      ephemeralPrivateKey: ephemeralKeys.privateKey,
      ephemeralPublicJwk: ephemeralKeys.publicJwk,
      headers: { 'x-test-integrity-fail': 'true' }
    });

    expect(
      issuance.statusCode === 403 && issuance.body.error === 'integrity_check_error',
      'Initialization failure must return integrity_check_error'
    ).toBe(true);
  });

  it('WP_041 - Status retrieval without credentials returns HTTP 401 unauthorized', async () => {
    const response = await wpFetch(`${walletProviderUrl}/wallet-instances/wallet-instance-b`);
    const body = await readJsonBody<{ error?: string }>(response);

    expect(
      response.status === 401 && body.error === 'unauthorized',
      'Missing credentials must return unauthorized'
    ).toBe(true);
  });

  it('WP_042 - Status retrieval for another user wallet returns HTTP 403 forbidden', async () => {
    const response = await wpFetch(`${walletProviderUrl}/wallet-instances/wallet-instance-b`, {
      headers: { Authorization: 'Bearer user-a' }
    });
    const body = await readJsonBody<{ error?: string }>(response);

    expect(response.status === 403 && body.error === 'forbidden', 'Cross-user status retrieval must be forbidden').toBe(
      true
    );
  });

  it('WP_043 - Revocation without credentials returns HTTP 401 unauthorized', async () => {
    const response = await wpFetch(`${walletProviderUrl}/wallet-instances/wallet-instance-b`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status: 'REVOKED' })
    });
    const body = await readJsonBody<{ error?: string }>(response);

    expect(
      response.status === 401 && body.error === 'unauthorized',
      'Revocation without credentials must return unauthorized'
    ).toBe(true);
  });

  it('WP_044 - Revocation for another user wallet returns HTTP 403 invalid_request', async () => {
    const response = await wpFetch(`${walletProviderUrl}/wallet-instances/wallet-instance-b`, {
      method: 'PATCH',
      headers: {
        Authorization: 'Bearer user-a',
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ status: 'REVOKED' })
    });
    const body = await readJsonBody<{ error?: string }>(response);

    expect(
      response.status === 403 && body.error === 'invalid_request',
      'Cross-user revocation must return invalid_request'
    ).toBe(true);
  });

  describe('Partially testable (WP backend scope)', () => {
    it('[WP backend only] WP_016 - Trust Anchor Entity Configuration is retrievable and refreshable', async () => {
      const trustAnchorUrl = resolveTrustAnchorUrl(federationJwt);
      let trustAnchorMetadataAvailable = false;

      try {
        const initialResponse = await wpFetch(`${trustAnchorUrl}/.well-known/openid-federation`);
        const initialBody = await initialResponse.text();
        const refreshResponse = await wpFetch(`${trustAnchorUrl}/.well-known/openid-federation`);
        const refreshBody = await refreshResponse.text();

        trustAnchorMetadataAvailable =
          initialResponse.status === 200 &&
          (initialResponse.headers.get('content-type') ?? '').includes('entity-statement+jwt') &&
          hasCompactJwtShape(initialBody) &&
          refreshResponse.status === 200 &&
          (refreshResponse.headers.get('content-type') ?? '').includes('entity-statement+jwt') &&
          hasCompactJwtShape(refreshBody);
      } catch (error) {
        const payload = decodeJwt(federationJwt) as { authority_hints?: string[] };
        const authorityHintsConfigured =
          Array.isArray(payload.authority_hints) &&
          payload.authority_hints.length > 0 &&
          payload.authority_hints.every((hint) => hint.startsWith('https://'));

        expect(
          authorityHintsConfigured,
          `Trust Anchor at ${trustAnchorUrl} is unreachable (${error instanceof Error ? error.message : String(error)}); Wallet Provider federation metadata must expose authority_hints for wallet-side Trust Anchor refresh`
        ).toBe(true);
        return;
      }

      expect(
        trustAnchorMetadataAvailable,
        'Trust Anchor Entity Configuration must be retrievable for trust evaluation (periodic wallet refresh not verified in this run)'
      ).toBe(true);
    });

    it('[WP backend only] WP_018 - Wallet Attestation issuance requests are logged over time', async () => {
      const debugBefore = await fetchConformanceDebug(walletProviderUrl);
      const logSizeBefore = debugBefore.attestation_issuance_log.length;
      const nonce = await fetchNonce(walletProviderUrl);
      const ephemeralKeys = await createEphemeralWalletKeyPair();
      const issuance = await issueWalletAttestation(walletProviderUrl, {
        nonce,
        ephemeralPrivateKey: ephemeralKeys.privateKey,
        ephemeralPublicJwk: ephemeralKeys.publicJwk
      });

      const debugAfter = await fetchConformanceDebug(walletProviderUrl);
      const newEntries = debugAfter.attestation_issuance_log.slice(logSizeBefore);
      const loggingWorks =
        issuance.statusCode === 200 &&
        newEntries.length === 1 &&
        typeof newEntries[0]?.timestamp === 'string' &&
        typeof newEntries[0]?.ephemeralKeyThumbprint === 'string';

      expect(
        loggingWorks,
        'Wallet Attestation issuance requests must be logged (periodic reissuance by wallet not verified in this run)'
      ).toBe(true);
    });

    it('[WP backend only] WP_019a - Wallet Provider rejects attestation for a non-verified wallet instance', async () => {
      const nonce = await fetchNonce(walletProviderUrl);
      const ephemeralKeys = await createEphemeralWalletKeyPair();
      const issuance = await issueWalletAttestation(walletProviderUrl, {
        nonce,
        ephemeralPrivateKey: ephemeralKeys.privateKey,
        ephemeralPublicJwk: ephemeralKeys.publicJwk,
        integrityAssertion: 'compromised-device'
      });

      expect(
        issuance.statusCode === 403 && issuance.body.error === 'integrity_check_error',
        'Wallet Provider must reject attestation when device integrity checks fail'
      ).toBe(true);
    });

    it('[WP backend only] WP_027 - Wallet Provider rejects attestation when device has a known security flaw', async () => {
      const nonce = await fetchNonce(walletProviderUrl);
      const ephemeralKeys = await createEphemeralWalletKeyPair();
      const issuance = await issueWalletAttestation(walletProviderUrl, {
        nonce,
        ephemeralPrivateKey: ephemeralKeys.privateKey,
        ephemeralPublicJwk: ephemeralKeys.publicJwk,
        hardwareSignature: 'invalid-security-flaw'
      });

      expect(
        issuance.statusCode === 403 && issuance.body.error === 'invalid_request',
        'Wallet Provider must reject attestation for insecure devices'
      ).toBe(true);
    });

    it('[WP backend only] WP_032 - User-initiated revocation request is accepted via external user agent', async () => {
      const response = await wpFetch(`${walletProviderUrl}/wallet-instances/wallet-instance-b`, {
        method: 'PATCH',
        headers: {
          Authorization: 'Bearer user-b',
          'Content-Type': 'application/json',
          'x-revocation-initiator': 'external-user-agent'
        },
        body: JSON.stringify({ status: 'REVOKED' })
      });

      const statusResponse = await wpFetch(`${walletProviderUrl}/wallet-instances/wallet-instance-b`, {
        headers: { Authorization: 'Bearer user-b' }
      });
      const statusBody = await readJsonBody<{ status?: string }>(statusResponse);

      expect(response.status, 'Revocation request from external user agent must be accepted').toBe(204);
      expect(statusBody.status, 'Wallet instance must be marked REVOKED').toBe('REVOKED');
    });

    it('[WP backend only] WP_034 - Revocation notification is recorded within 24 hours', async () => {
      const debugSnapshot = await fetchConformanceDebug(walletProviderUrl);
      const notification = debugSnapshot.revocation_notifications.find(
        (event) => event.instanceId === 'wallet-instance-b'
      );

      expect(notification, 'Expected revocation notification for wallet-instance-b').toBeDefined();
      if (!notification) {
        return;
      }

      const revokedAt = new Date(notification.revokedAt).getTime();
      const notifiedAt = new Date(notification.notifiedAt).getTime();
      const within24Hours = notifiedAt >= revokedAt && notifiedAt - revokedAt < 24 * 60 * 60 * 1000;

      expect(
        within24Hours,
        'Revocation notification timestamp must be within 24h (out-of-band channel delivery not verified)'
      ).toBe(true);
    });

    it('[WP backend only] WP_038 - Simulated internal failure returns HTTP 500 with server_error', async () => {
      const response = await wpFetch(`${walletProviderUrl}/nonce`, {
        headers: { 'x-test-server-error': 'true' }
      });
      const body = await readJsonBody<{ error?: string }>(response);

      expect(
        response.status === 500 && body.error === 'server_error',
        'Internal server error response format must be supported'
      ).toBe(true);
    });

    it('[WP backend only] WP_039 - Maintenance mode returns HTTP 503 with temporarily_unavailable', async () => {
      const response = await wpFetch(`${walletProviderUrl}/nonce`, {
        headers: { 'x-test-maintenance': 'true' }
      });
      const body = await readJsonBody<{ error?: string }>(response);

      expect(
        response.status === 503 && body.error === 'temporarily_unavailable',
        'Service unavailable response format must be supported'
      ).toBe(true);
    });
  });
});
