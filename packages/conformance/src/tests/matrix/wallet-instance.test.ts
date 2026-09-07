import { loadConfig } from '@itw-conformance-tool/config';
import { DatabaseClient } from '@itw-conformance-tool/database';
import { SignJWT, calculateJwkThumbprint, exportJWK, generateKeyPair } from 'jose';
import { afterAll, beforeAll, describe } from 'vitest';

import { isObject, trimTrailingSlash } from '../../helpers/general.js';
import {
  type ObservedEvent,
  type ScenarioOutcome,
  type ScenarioRunner,
  assertConformanceOutcome,
  createProtocolObservedScenarioRunner,
  createSqliteScenarioEventBridge,
  walletInstanceScenarioRegistry,
  wpWalletProviderHappyScenario
} from '../../index.js';

const SYNTACTICALLY_VALID_WALLET_INSTANCE_ID = 'd2FsbGV0LWluc3RhbmNlLXdwLTA0MQ';
const PERMITTED_ENTITY_CONFIGURATION_SIGNATURE_ALGORITHMS = ['ES256', 'ES384', 'ES512'];

type CapturedJsonResponse = {
  body: unknown;
  bodyParseError: unknown;
  bodyText: string;
  response: Response;
};

describe('Test Cases for Wallet Instance', async () => {
  let outcome: ScenarioOutcome;
  let events: ObservedEvent[];
  let runner: ScenarioRunner;
  let db: DatabaseClient;
  let integrityCheckErrorRegistration: CapturedJsonResponse;
  let malformedRegistration: CapturedJsonResponse;
  let unauthenticatedRevocation: CapturedJsonResponse;
  let unauthenticatedStatusRetrieval: CapturedJsonResponse;
  let validationErrorRegistration: CapturedJsonResponse;
  let walletProviderUrl: string;

  beforeAll(async () => {
    const config = loadConfig();
    walletProviderUrl = config['wallet-provider'].url;
    db = new DatabaseClient(config.global.data_dir);

    const federation = config['trust-anchor'].url;
    const walletProvider = config['wallet-provider'].local_url;
    runner = createProtocolObservedScenarioRunner({
      endpoints: { federation, walletProvider },
      eventBridgeFactory: createSqliteScenarioEventBridge({ db }),
      registry: walletInstanceScenarioRegistry
    });

    const walletInstancesUrl = trimTrailingSlash(walletProviderUrl) + '/wallet-instances';
    malformedRegistration = await postWalletInstanceRegistration(walletInstancesUrl, {});
    validationErrorRegistration = await postWalletInstanceRegistration(walletInstancesUrl, {
      nonce: 'd2JhY2NhbG91cmVqdWFuZGFt',
      hardware_key_tag: 'not base64url!',
      key_attestation: 'well_formed_key_attestation'
    });
    integrityCheckErrorRegistration = await postWalletInstanceRegistration(walletInstancesUrl, {
      nonce: 'd2JhY2NhbG91cmVqdWFuZGFt',
      hardware_key_tag: 'WQhyDymFKsP95iFqpzdEDWW4l7aVna2Fn4JCeWHYtbU=',
      key_attestation: 'integrity_check_error'
    });

    const walletInstanceUrl =
      trimTrailingSlash(walletProviderUrl) +
      '/wallet-instances/' +
      encodeURIComponent(SYNTACTICALLY_VALID_WALLET_INSTANCE_ID);
    unauthenticatedStatusRetrieval = await captureJsonResponse(walletInstanceUrl, { method: 'GET' });
    unauthenticatedRevocation = await captureJsonResponse(walletInstanceUrl, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ status: 'REVOKED' })
    });
  });

  afterAll(async () => {
    await runner.close();
    db.close();
  });

  describe('Happy path', () => {
    beforeAll(async () => {
      const session = await runner.start(wpWalletProviderHappyScenario.id);
      try {
        await session.showInstructions();
        outcome = await session.awaitVerdict();
        events = session.events.all();
      } finally {
        await session.stop();
      }
    }, wpWalletProviderHappyScenario.timeouts.vitestTestMs);

    test(
      `WP_023: Wallet Instance successfully uses Federation API endpoints (.well-known/openid-federation, /fetch) to retrieve current metadata and configurations of the Wallet Provider.`,
      () => {
        expect(events, 'Happy-path scenario should capture protocol evidence').not.toHaveLength(0);
        assertConformanceOutcome(outcome, { expected: 'PASS' });
      },
      wpWalletProviderHappyScenario.timeouts.vitestTestMs
    );

    test(
      'WP_026: To perform a Wallet Attestation request, Wallet Instance successfully generates a new ephemeral asymmetric key pair.',
      () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        const attestationEvent = events.find((event) => event.name === 'wallet_attestation.requested');
        expect(attestationEvent, 'Happy-path scenario must observe the Wallet Attestation request').toBeDefined();
        if (!attestationEvent) {
          throw new Error('Missing wallet_attestation.requested evidence');
        }

        expect(requiredDiagnosticString(attestationEvent, 'endpoint')).toBe('/wallet-instance-attestation');
        expect(requiredDiagnosticString(attestationEvent, 'method')).toBe('POST');
        expect(requiredDiagnosticString(attestationEvent, 'outcome')).toBe('success');
        expect(requiredDiagnosticString(attestationEvent, 'assertionAlg')).toBeOneOf(
          PERMITTED_ENTITY_CONFIGURATION_SIGNATURE_ALGORITHMS
        );

        expect(
          requiredDiagnosticBoolean(attestationEvent, 'cnfJwkAsymmetric'),
          'Wallet Attestation request cnf.jwk must identify an asymmetric public key'
        ).toBe(true);
        expect(
          requiredDiagnosticBoolean(attestationEvent, 'cnfJwkPublicOnly'),
          'Wallet Attestation request cnf.jwk must not expose private or symmetric key material'
        ).toBe(true);
        expect(
          requiredDiagnosticBoolean(attestationEvent, 'assertionKidMatchesCnfJwkThumbprint'),
          'Wallet Attestation request kid must identify the cnf.jwk thumbprint'
        ).toBe(true);
        expect(
          requiredDiagnosticBoolean(attestationEvent, 'proofVerifiedWithCnfJwk'),
          'Wallet Attestation request signature must verify with the cnf.jwk public key'
        ).toBe(true);

        const assertionKid = requiredDiagnosticString(attestationEvent, 'assertionKid');
        const cnfJwkThumbprint = requiredDiagnosticString(attestationEvent, 'cnfJwkThumbprint');
        expect(assertionKid, 'Wallet Attestation request kid must equal the cnf.jwk thumbprint').toBe(cnfJwkThumbprint);
      },
      wpWalletProviderHappyScenario.timeouts.vitestTestMs
    );
  });

  test('WP_019a: Wallet Provider rejects an attestation request from a Wallet Instance that fails authenticity, integrity, or genuineness checks', async () => {
    const endpoint = trimTrailingSlash(walletProviderUrl) + '/wallet-instance-attestation';

    const assertion =
      'eyJhbGciOiJFUzI1NiIsInR5cCI6IldBTExFVC1JTlNUQU5DRS1BVFRFU1RBVElPTitKV1QifQ.eyJpc3MiOiJpbnZhbGlkIiwic3ViIjoiaW52YWxpZCIsImF1ZCI6ImludmFsaWQifQ.invalid_signature';

    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ assertion }),
      signal: AbortSignal.timeout(10_000)
    });

    expect(
      response.status,
      'Wallet Provider must reject invalid attestation requests with a 4xx HTTP status code (e.g., 400 or 401)'
    ).toBeGreaterThanOrEqual(400);

    expect(
      response.status,
      'Wallet Provider must reject invalid attestation requests with a 4xx HTTP status code'
    ).toBeLessThan(500);
  });

  test('WP_027: Wallet Provider verifies the device meets its minimum security requirements and is free of known security flaws; if not, the Wallet Attestation Request is rejected', async () => {
    const endpoint = trimTrailingSlash(walletProviderUrl) + '/wallet-instance-attestation';
    const assertion = await createWalletInstanceAttestationRequestAssertion(walletProviderUrl, 'invalid');

    const integrityCheckErrorAttestation = await captureJsonResponse(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ assertion })
    });

    expect(
      integrityCheckErrorAttestation.response.status,
      'Wallet Provider must reject an attestation request with an invalid integrity_assertion using HTTP 403 Forbidden'
    ).toBe(403);

    const body = expectWalletInstanceManagementErrorBody(
      integrityCheckErrorAttestation,
      'Wallet Instance attestation device integrity error'
    );

    expect(
      body.error,
      'Wallet Provider must return error "integrity_check_error" when the device integrity assertion fails'
    ).toBe('integrity_check_error');
  });

  test('WP_035: Wallet Provider handles malformed Wallet Instance registration requests with the expected HTTP error status', () => {
    expect(
      malformedRegistration.response.status,
      'Malformed Wallet Instance registration must not return a successful response or redirect; expected HTTP 400 Bad Request'
    ).toBeGreaterThanOrEqual(400);

    expect(
      malformedRegistration.response.status,
      'Malformed Wallet Instance registration must use a client error status, not a server error status'
    ).toBeLessThan(500);

    expect(
      malformedRegistration.response.status,
      'Malformed Wallet Instance registration must return HTTP 400 Bad Request'
    ).toBe(400);
  });

  test('WP_035a: Wallet Provider error responses use application/json with error and error_description', () => {
    expectWalletInstanceManagementErrorBody(malformedRegistration, 'Malformed Wallet Instance registration error');
  });

  test('WP_036: Wallet Provider maps malformed Wallet Instance registration requests to bad_request', () => {
    expect(
      malformedRegistration.response.status,
      'Malformed Wallet Instance registration must return HTTP 400 Bad Request'
    ).toBe(400);

    const body = expectWalletInstanceManagementErrorBody(
      malformedRegistration,
      'Malformed Wallet Instance registration error'
    );

    expect(body.error, 'Malformed Wallet Instance registration must return error "bad_request"').toBe('bad_request');
  });

  test('WP_037: Wallet Provider maps semantically invalid Wallet Instance registration requests to validation_error', () => {
    expect(
      validationErrorRegistration.response.status,
      'Semantically invalid Wallet Instance registration must return HTTP 422 Unprocessable Content'
    ).toBe(422);

    const body = expectWalletInstanceManagementErrorBody(
      validationErrorRegistration,
      'Semantically invalid Wallet Instance registration error'
    );

    expect(body.error, 'Semantically invalid Wallet Instance registration must return error "validation_error"').toBe(
      'validation_error'
    );
  });

  test("WP_040: Wallet Provider rejects devices that do not meet the provider's security requirements", () => {
    expect(
      integrityCheckErrorRegistration.response.status,
      "Wallet Instance registration from a device that does not meet the provider's security requirements must return HTTP 403 Forbidden"
    ).toBe(403);

    const body = expectWalletInstanceManagementErrorBody(
      integrityCheckErrorRegistration,
      'Wallet Instance registration device integrity error'
    );

    expect(
      body.error,
      'Wallet Instance registration device integrity failure must return error "integrity_check_error"'
    ).toBe('integrity_check_error');
  });

  test('WP_041: Wallet Provider rejects Wallet Instance status retrieval without valid authentication credentials', () => {
    expect(
      unauthenticatedStatusRetrieval.response.status,
      'Wallet Instance status retrieval without valid authentication credentials must return HTTP 401 Unauthorized'
    ).toBe(401);

    const body = expectWalletInstanceManagementErrorBody(
      unauthenticatedStatusRetrieval,
      'Unauthenticated Wallet Instance status retrieval error'
    );

    expect(
      body.error,
      'Wallet Instance status retrieval without valid authentication credentials must return error "unauthorized"'
    ).toBe('unauthorized');
  });

  test('WP_043: Wallet Provider rejects Wallet Instance revocation without valid authentication credentials', () => {
    expect(
      unauthenticatedRevocation.response.status,
      'Wallet Instance revocation without valid authentication credentials must return HTTP 401 Unauthorized'
    ).toBe(401);

    const body = expectWalletInstanceManagementErrorBody(
      unauthenticatedRevocation,
      'Unauthenticated Wallet Instance revocation error'
    );

    expect(
      body.error,
      'Wallet Instance revocation without valid authentication credentials must return error "unauthorized"'
    ).toBe('unauthorized');
  });
});

async function captureJsonResponse(url: string, init: RequestInit = {}): Promise<CapturedJsonResponse> {
  const response = await fetch(url, {
    ...init,
    redirect: 'manual',
    signal: AbortSignal.timeout(10_000)
  });

  const bodyText = await response.text();
  try {
    return {
      body: JSON.parse(bodyText) as unknown,
      bodyParseError: undefined,
      bodyText,
      response
    };
  } catch (error) {
    return {
      body: undefined,
      bodyParseError: error,
      bodyText,
      response
    };
  }
}

async function postWalletInstanceRegistration(
  walletInstancesUrl: string,
  body: Record<string, unknown>
): Promise<CapturedJsonResponse> {
  return captureJsonResponse(walletInstancesUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(body)
  });
}

function requiredDiagnosticBoolean(event: ObservedEvent, key: string): boolean {
  const value = event.diagnostic?.[key];
  if (typeof value !== 'boolean') {
    throw new Error(`${event.name} evidence is missing the ${key} diagnostic`);
  }

  return value;
}

function requiredDiagnosticString(event: ObservedEvent, key: string): string {
  const value = event.diagnostic?.[key];
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${event.name} evidence is missing the ${key} diagnostic`);
  }

  return value;
}

async function createWalletInstanceAttestationRequestAssertion(
  walletProviderUrl: string,
  integrityAssertion: string
): Promise<string> {
  const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
  const publicJwk = await exportJWK(publicKey);
  const kid = await calculateJwkThumbprint(publicJwk);
  const now = Math.floor(Date.now() / 1_000);

  return new SignJWT({
    iss: trimTrailingSlash(walletProviderUrl),
    exp: now + 300,
    iat: now,
    nonce: 'valid_nonce',
    hardware_signature: 'valid_hardware_signature',
    integrity_assertion: integrityAssertion,
    hardware_key_tag: 'valid_hardware_key_tag',
    cnf: {
      jwk: publicJwk
    },
    platform: 'iOS',
    wallet_solution_id: 'Wallet-mobile',
    wallet_solution_version: '1.1.0'
  })
    .setProtectedHeader({
      alg: 'ES256',
      kid,
      typ: 'wia-request+jwt'
    })
    .sign(privateKey);
}

function expectWalletInstanceManagementErrorBody(
  capturedResponse: CapturedJsonResponse,
  errorContext: string
): Record<string, unknown> {
  const contentType = capturedResponse.response.headers.get('content-type') ?? '';

  expect(contentType, `${errorContext} response must use the application/json media type`).toMatch(
    /^application\/json(?:\s*;|$)/i
  );

  expect(
    capturedResponse.bodyParseError,
    `${errorContext} response body must be valid JSON. Received: ${capturedResponse.bodyText}`
  ).toBeUndefined();

  expect(capturedResponse.body, `${errorContext} response body must be a JSON object`).toSatisfy(isObject);

  if (!isObject(capturedResponse.body)) {
    throw new Error(`${errorContext} response body is not a JSON object`);
  }

  const body = capturedResponse.body as Record<string, unknown>;

  expect(body.error, `${errorContext} response must contain a non-empty error`).toEqual(expect.any(String));
  expect(body.error, `${errorContext} response error value must not be empty`).toSatisfy(
    (value) => typeof value === 'string' && value.trim().length > 0
  );

  expect(body.error_description, `${errorContext} response must contain a non-empty error_description`).toEqual(
    expect.any(String)
  );
  expect(body.error_description, `${errorContext} response error_description value must not be empty`).toSatisfy(
    (value) => typeof value === 'string' && value.trim().length > 0
  );

  return body;
}
