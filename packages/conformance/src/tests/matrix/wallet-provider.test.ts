import { loadConfig } from '@itw-conformance-tool/config';
import {
  SignJWT,
  calculateJwkThumbprint,
  createLocalJWKSet,
  decodeProtectedHeader,
  exportJWK,
  generateKeyPair,
  importJWK,
  jwtVerify
} from 'jose';
import { beforeAll, describe, expect, test } from 'vitest';

import { isHttpsUrl, isObject, trimTrailingSlash } from '../../helpers/general.js';
import {
  decodeEntityConfiguration,
  expectPublicJwk,
  expectWalletMetadata,
  resolveWalletSolutionJwks
} from '../../helpers/provider.js';

const PERMITTED_ENTITY_CONFIGURATION_SIGNATURE_ALGORITHMS = ['ES256', 'ES384', 'ES512'];
const SIGNING_OPERATIONS = ['sign', 'verify'];
const ENCRYPTION_OPERATIONS = ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey', 'deriveKey', 'deriveBits'];
const SYNTACTICALLY_VALID_WALLET_INSTANCE_ID = 'd2FsbGV0LWluc3RhbmNlLXdwLTA0MQ';

type CapturedJsonResponse = {
  body: unknown;
  bodyParseError: unknown;
  bodyText: string;
  response: Response;
};

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

describe('Test Cases for Wallet Provider Backend', () => {
  const config = loadConfig();
  const walletProviderUrl = config['wallet-provider'].url;

  let entityConfiguration: string;
  let entityConfigurationResponse: Response;
  let integrityCheckErrorRegistration: CapturedJsonResponse;
  let malformedRegistration: CapturedJsonResponse;
  let unauthenticatedRevocation: CapturedJsonResponse;
  let unauthenticatedStatusRetrieval: CapturedJsonResponse;
  let validationErrorRegistration: CapturedJsonResponse;

  beforeAll(async () => {
    const discoveryUrl = trimTrailingSlash(walletProviderUrl) + '/.well-known/openid-federation';
    entityConfigurationResponse = await fetch(discoveryUrl, {
      signal: AbortSignal.timeout(10_000)
    });

    entityConfiguration = await entityConfigurationResponse.text();

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

  const expectWalletInstanceManagementErrorBody = (
    capturedResponse: CapturedJsonResponse,
    errorContext: string
  ): Record<string, unknown> => {
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
  };

  test('WP_001: Entity Configuration publication', () => {
    expect(entityConfigurationResponse.status, 'Entity Configuration endpoint must return HTTP 200').toBe(200);
    expect(
      entityConfigurationResponse.headers.get('content-type'),
      'Entity Configuration response must use the application/entity-statement+jwt media type'
    ).toMatch(/^application\/entity-statement\+jwt(?:;|$)/i);
    expect(entityConfiguration, 'Entity Configuration response must be a compact JWT').toMatch(/^[^.]+\.[^.]+\.[^.]+$/);
  });

  test('WP_002: Entity Configuration cryptography', async () => {
    const claims = decodeEntityConfiguration(entityConfiguration);
    const protectedHeader = decodeProtectedHeader(entityConfiguration);

    expect(claims.iss, 'Entity Configuration must contain a string issuer claim').toEqual(expect.any(String));
    expect(claims.sub, 'Entity Configuration subject must equal its issuer').toBe(claims.iss);
    expect(claims.jwks, 'Entity Configuration must contain a JWKS with a keys array').toEqual(
      expect.objectContaining({ keys: expect.any(Array) })
    );

    expect(protectedHeader.typ, 'Entity Configuration JWT type must be entity-statement+jwt').toBe(
      'entity-statement+jwt'
    );

    await jwtVerify(entityConfiguration, createLocalJWKSet(claims.jwks), {
      issuer: claims.iss,
      requiredClaims: ['exp', 'iat'],
      subject: claims.iss
    });
  });

  test('WP_002a: Entity Configuration JWT alg header parameter', () => {
    const { alg } = decodeProtectedHeader(entityConfiguration);

    expect(alg, 'Entity Configuration JWT signing algorithm must be ES256, ES384, or ES512').toBeOneOf(
      PERMITTED_ENTITY_CONFIGURATION_SIGNATURE_ALGORITHMS
    );
    expect(alg, 'Entity Configuration JWT must not use the unsecured none algorithm').not.toBe('none');
  });

  test('WP_002b: Entity Configuration JWT kid header parameter', async () => {
    const claims = decodeEntityConfiguration(entityConfiguration);
    const { kid } = decodeProtectedHeader(entityConfiguration);

    expect(kid, 'Entity Configuration JWT header must contain a string kid').toEqual(expect.any(String));

    const signingKey = claims.jwks.keys.find((key) => key.kid === kid);

    expect(signingKey, 'Entity Configuration JWT kid must identify a public key in the JWKS').toBeDefined();
    if (!signingKey) {
      throw new Error('Entity Configuration signing key is missing from the JWKS');
    }

    await expect(
      calculateJwkThumbprint(signingKey),
      'Entity Configuration JWT kid must equal the signing public key thumbprint'
    ).resolves.toBe(kid);
  });

  test('WP_002c: Entity Configuration JWT typ header parameter', () => {
    const { typ } = decodeProtectedHeader(entityConfiguration);

    expect(typ, 'Entity Configuration JWT type must be entity-statement+jwt').toBe('entity-statement+jwt');
  });

  test('WP_002d: Entity Configuration issuer and subject payload claims', () => {
    const { iss, sub } = decodeEntityConfiguration(entityConfiguration);

    expect(iss, 'Entity Configuration issuer must equal the Wallet Provider public URL').toBe(walletProviderUrl);
    expect(sub, 'Entity Configuration subject must equal the Wallet Provider public URL').toBe(walletProviderUrl);
  });

  test('WP_002e: Entity Configuration validity', () => {
    const { exp, iat } = decodeEntityConfiguration(entityConfiguration);
    const now = Math.floor(Date.now() / 1_000);

    expect(iat, 'Entity Configuration issued-at claim must be a Unix timestamp').toSatisfy(Number.isSafeInteger);
    expect(exp, 'Entity Configuration expiration claim must be a Unix timestamp').toSatisfy(Number.isSafeInteger);
    expect(iat, 'Entity Configuration issued-at claim must not be in the future').toBeLessThanOrEqual(now);
    expect(exp, 'Entity Configuration expiration claim must be in the future').toBeGreaterThan(now);
    expect(exp, 'Entity Configuration expiration claim must follow its issued-at claim').toBeGreaterThan(iat);
  });

  test('WP_002f: Entity Configuration authority hints', () => {
    const { authority_hints: authorityHints } = decodeEntityConfiguration(entityConfiguration);

    expect(authorityHints, 'Entity Configuration authority hints must be an array').toEqual(expect.any(Array));
    expect(
      authorityHints,
      'Entity Configuration must identify at least one immediate superior entity'
    ).not.toHaveLength(0);

    for (const authorityHint of authorityHints as string[]) {
      expect(authorityHint, 'Each authority hint must be an HTTPS Entity Identifier URL').toSatisfy((value) =>
        isHttpsUrl(value, false)
      );
    }
  });

  test('WP_002g: Entity Configuration public keys', async () => {
    const { jwks } = decodeEntityConfiguration(entityConfiguration);
    const { alg } = decodeProtectedHeader(entityConfiguration);

    expect(jwks, 'Entity Configuration must contain a JWKS object').toSatisfy(isObject);
    expect(jwks, 'Entity Configuration JWKS must contain a keys array').toEqual(
      expect.objectContaining({ keys: expect.any(Array) })
    );

    const publicKeys = jwks.keys;
    expect(publicKeys, 'Entity Configuration JWKS must contain at least one public key').not.toHaveLength(0);

    for (const key of publicKeys) {
      expectPublicJwk(key, 'Entity Configuration JWKS');
      await expect(
        importJWK(key, key.alg ?? alg),
        'Each Entity Configuration key must be a valid public JWK'
      ).resolves.toBeDefined();
    }
  });

  test('WP_002h: Entity Configuration metadata', () => {
    const ec = decodeEntityConfiguration(entityConfiguration);
    const metadata = expectWalletMetadata(ec.metadata);

    expect(
      metadata.wallet_solution,
      'Entity Configuration metadata must contain wallet_solution metadata'
    ).toBeDefined();

    const federationEntity = metadata.federation_entity;
    if (federationEntity === undefined) {
      return;
    }

    expect(federationEntity, 'federation_entity metadata must be an object when present').toSatisfy(isObject);

    expect(
      Object.values(federationEntity),
      'federation_entity metadata must not contain null-valued parameters'
    ).not.toContain(null);

    const federationEndpoints = [
      'federation_fetch_endpoint',
      'federation_list_endpoint',
      'federation_resolve_endpoint',
      'federation_trust_mark_status_endpoint',
      'federation_trust_mark_list_endpoint',
      'federation_trust_mark_endpoint',
      'federation_historical_keys_endpoint'
    ];

    for (const endpointName of federationEndpoints) {
      const endpoint = federationEntity[endpointName];
      if (endpoint !== undefined) {
        expect(endpoint, `${endpointName} must be an HTTPS URL without a fragment`).toSatisfy(isHttpsUrl);
      }
    }
  });

  test('WP_003: Metadata key usage', async () => {
    const ec = decodeEntityConfiguration(entityConfiguration);
    const metadata = expectWalletMetadata(ec.metadata);
    const walletSolution = metadata.wallet_solution;

    expect(walletSolution, 'Entity Configuration metadata must contain wallet_solution metadata').toBeDefined();

    if (walletSolution === undefined) {
      throw new Error('Entity Configuration metadata does not contain wallet_solution metadata');
    }

    const keys = await resolveWalletSolutionJwks(ec, walletSolution);

    expect(keys.length, 'Wallet Solution metadata must resolve to at least one public key').toBeGreaterThan(0);

    for (const key of keys) {
      if (key.use !== undefined) {
        expect(key.use, 'When present, JWK use must be sig or enc').toBeOneOf(['sig', 'enc']);
      }

      if (key.key_ops !== undefined) {
        expect(key.key_ops.length, 'key_ops must not be empty when present').toBeGreaterThan(0);

        const allowedOperations =
          key.use === 'sig'
            ? SIGNING_OPERATIONS
            : key.use === 'enc'
              ? ENCRYPTION_OPERATIONS
              : [...SIGNING_OPERATIONS, ...ENCRYPTION_OPERATIONS];

        for (const operation of key.key_ops) {
          expect(allowedOperations, `Unsupported or inconsistent key operation: ${operation}`).toContain(operation);
        }
      }

      if (key.use === 'sig' && key.key_ops !== undefined) {
        expect(
          key.key_ops.every((operation) => SIGNING_OPERATIONS.includes(operation)),
          'A sig key must not declare encryption operations'
        ).toBe(true);
      }

      if (key.use === 'enc' && key.key_ops !== undefined) {
        expect(
          key.key_ops.every((operation) => ENCRYPTION_OPERATIONS.includes(operation)),
          'An enc key must not declare signing operations'
        ).toBe(true);
      }
    }
  });

  test('WP_004: Metadata key reference', () => {
    const ec = decodeEntityConfiguration(entityConfiguration);
    const metadata = expectWalletMetadata(ec.metadata);
    const keyReferences = ['jwks', 'jwks_uri', 'signed_jwks_uri'];
    const presentKeyReferences = keyReferences.filter((claim) => metadata.wallet_solution?.[claim] !== undefined);

    expect(
      presentKeyReferences,
      'wallet_solution metadata must contain exactly one public key reference: jwks, jwks_uri, or signed_jwks_uri'
    ).toHaveLength(1);
  });

  test('WP_004a: JWKS by value', async () => {
    const ec = decodeEntityConfiguration(entityConfiguration);
    const { alg } = decodeProtectedHeader(entityConfiguration);
    const metadata = expectWalletMetadata(ec.metadata);
    const walletSolution = metadata.wallet_solution;

    expect(walletSolution, 'Entity Configuration metadata must contain wallet_solution metadata').toBeDefined();
    if (walletSolution?.jwks === undefined) {
      return;
    }

    const keys = await resolveWalletSolutionJwks(ec, walletSolution);

    expect(keys, 'wallet_solution jwks claim must contain at least one public key').not.toHaveLength(0);
    for (const key of keys) {
      expectPublicJwk(key, 'wallet_solution jwks claim');
      await expect(
        importJWK(key, key.alg ?? alg),
        'Each wallet_solution jwks claim key must be a valid public JWK'
      ).resolves.toBeDefined();
    }
  });

  test('WP_004b: JWKS by reference', async () => {
    const ec = decodeEntityConfiguration(entityConfiguration);
    const { alg } = decodeProtectedHeader(entityConfiguration);
    const metadata = expectWalletMetadata(ec.metadata);
    const walletSolution = metadata.wallet_solution;

    expect(walletSolution, 'Entity Configuration metadata must contain wallet_solution metadata').toBeDefined();
    if (walletSolution?.jwks_uri === undefined) {
      return;
    }

    const keys = await resolveWalletSolutionJwks(ec, walletSolution);

    expect(keys, 'wallet_solution jwks_uri JWKS must contain at least one public key').not.toHaveLength(0);
    for (const key of keys) {
      expectPublicJwk(key, 'wallet_solution jwks_uri JWKS');
      await expect(
        importJWK(key, key.alg ?? alg),
        'Each wallet_solution jwks_uri JWKS key must be a valid public JWK'
      ).resolves.toBeDefined();
    }
  });

  test('WP_004c: Signed JWKS URI', async () => {
    const ec = decodeEntityConfiguration(entityConfiguration);
    const { alg } = decodeProtectedHeader(entityConfiguration);
    const metadata = expectWalletMetadata(ec.metadata);
    const walletSolution = metadata.wallet_solution;

    if (walletSolution?.signed_jwks_uri === undefined) {
      return;
    }

    const keys = await resolveWalletSolutionJwks(ec, walletSolution);

    expect(keys, 'wallet_solution signed_jwks_uri JWT payload must contain at least one public key').not.toHaveLength(
      0
    );
    for (const key of keys) {
      expectPublicJwk(key, 'wallet_solution signed_jwks_uri JWT payload');
      await expect(
        importJWK(key, key.alg ?? alg),
        'Each signed_jwks_uri JWKS key must be a valid public JWK'
      ).resolves.toBeDefined();
    }
  });

  // Wallet Instance Tests

  test('WP_019a: Wallet Provider rejects an attestation request from a Wallet Instance that fails authenticity, integrity, or genuineness checks', async () => {
    const endpoint = trimTrailingSlash(walletProviderUrl) + '/wallet-instance-attestation';

    const invalidAssertionBody = new URLSearchParams({
      assertion:
        'eyJhbGciOiJFUzI1NiIsInR5cCI6IldBTExFVC1JTlNUQU5DRS1BVFRFU1RBVElPTitKV1QifQ.eyJpc3MiOiJpbnZhbGlkIiwic3ViIjoiaW52YWxpZCIsImF1ZCI6ImludmFsaWQifQ.invalid_signature'
    });

    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: invalidAssertionBody.toString(),
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
