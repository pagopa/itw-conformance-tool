import { createHash, randomUUID } from 'node:crypto';

import { loadConfig, type ConfigSchemaType } from '@itw-conformance-tool/config';
import { DatabaseClient } from '@itw-conformance-tool/database';
import { createServiceControlClient, type ServiceControlClient } from '@itw-conformance-tool/ipc';
import {
  decodeJwt,
  decodeJwtHeader,
  htuFromRequestUrl,
  parseAccessTokenRequest,
  parsePushedAuthorizationRequest,
  verifyClientAttestationPopJwt,
  zDpopJwtHeader,
  zDpopJwtPayload,
  zItWalletClientAttestationPopJwtHeader,
  zItWalletClientAttestationPopJwtPayload,
  IT_WALLET_CLIENT_ATTESTATION_POP_ALLOWED_ALG_VALUES
} from '@pagopa/io-wallet-oauth2';
import { zCredentialRequestV1_3, zProofJwtHeaderV1_3, zProofJwtPayload } from '@pagopa/io-wallet-oid4vci';
import { IoWalletSdkConfig, ItWalletSpecsVersion, type HttpMethod } from '@pagopa/io-wallet-utils';
import { calculateJwkThumbprint, importJWK, jwtVerify, type JWK } from 'jose';
import { afterAll, beforeAll, describe, expect, test } from 'vitest';

import { trimTrailingSlash } from '../../helpers/general.js';
import { isRfc7636CodeVerifier } from '../../helpers/issuance.js';
import { decodeEntityConfiguration } from '../../helpers/provider.js';
import {
  assertConformanceOutcome,
  createProtocolObservedScenarioRunner,
  createSqliteScenarioEventBridge,
  issuanceScenarioRegistry,
  wp046aScenario,
  WP_UNSUPPORTED_CREDENTIAL_CONFIGURATION_ID,
  wpUnsupportedCredentialOfferScenario,
  wp059Scenario,
  wp060TypeMismatchScenario,
  wp061Scenario,
  wp062aScenario,
  wp062bScenario,
  wpDeferredScenario,
  wp054MissingCodeScenario,
  wp054aInvalidStateScenario,
  wp054bInvalidIssuerScenario,
  wpCiHappyScenario
} from '../../index.js';
import { httpsRequest } from '../../utils/request.js';

import type { HttpResponseSentEvent, ObservedEvent, ScenarioOutcome, ScenarioRunner } from '../../index.js';
import type { CallbackContext, DpopJwtHeader, DpopJwtPayload } from '@pagopa/io-wallet-oauth2';
import type { CredentialRequestV1_3, ProofJwtHeaderV1_3, ProofJwtPayload } from '@pagopa/io-wallet-oid4vci';

function toHeaders(value: unknown): Headers {
  if (value === null || typeof value !== 'object') {
    throw new Error('issuer.par.requested evidence is missing header data');
  }

  const entries = Object.entries(value as Record<string, unknown>).filter(
    (entry): entry is [string, string] => typeof entry[1] === 'string'
  );

  return new Headers(entries);
}

function requiredDiagnosticString(event: ObservedEvent, key: string): string {
  const value = event.diagnostic?.[key];
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${event.name} evidence is missing the ${key} diagnostic`);
  }

  return value;
}

function requiredDiagnosticNumber(event: ObservedEvent, key: string): number {
  const value = event.diagnostic?.[key];
  if (typeof value !== 'number') {
    throw new Error(`${event.name} evidence is missing the ${key} diagnostic`);
  }

  return value;
}

function findHttpResponseSentEvent(
  events: ObservedEvent[],
  requestId: string | undefined
): HttpResponseSentEvent | undefined {
  return events.find(
    (event): event is HttpResponseSentEvent => event.name === 'http.response.sent' && event.requestId === requestId
  );
}

function sha256Base64Url(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('base64url');
}

function decodeCredentialOfferUri(uri: string): { credential_configuration_ids?: string[] } {
  const credentialOffer = new URL(uri).searchParams.get('credential_offer');
  if (!credentialOffer) {
    throw new Error('Credential offer URI is missing the credential_offer parameter');
  }

  return JSON.parse(credentialOffer) as { credential_configuration_ids?: string[] };
}

/**
 * Minimal jose-based `verifyJwt` callback adapter, local to this test file, so
 * that WP_052c can exercise `verifyClientAttestationPopJwt`'s cryptographic
 * verification without importing production application code (e.g.
 * `apps/itw-credential-issuer/src/domain/crypto.ts`) into the conformance
 * package. Only the `jwk` signer method is handled because
 * `verifyClientAttestationPopJwt` is always invoked here with an explicit
 * public JWK (the Wallet Attestation's `cnf.jwk`).
 */
const verifyJwtWithJwk: NonNullable<CallbackContext['verifyJwt']> = async (signer, jwt) => {
  if (signer.method !== 'jwk') {
    return { verified: false };
  }

  try {
    const publicKey = await importJWK(signer.publicJwk as JWK, signer.alg);
    await jwtVerify(jwt.compact, publicKey, { clockTolerance: 300 });
    return { verified: true, signerJwk: signer.publicJwk };
  } catch {
    return { verified: false };
  }
};

// Tolerance (seconds) used to assert that the DPoP proof's `iat` claim is
// recent relative to the observed `issuer.token.requested` event timestamp,
// matching the clock tolerance already used for JWT signature verification
// in this file.
const DPOP_IAT_FRESHNESS_TOLERANCE_SECONDS = 300;

// Set by the CLI's local control relay (`itwct test issuance`/`itwct test`)
// before spawning this Vitest process; see `apps/cli/src/commands/runTests.ts`.
const SERVICE_CONTROL_ENDPOINT_ENV_VAR = 'ITWCT_SERVICE_CONTROL_ENDPOINT';

describe('Test Cases for Issuance Phase', () => {
  let runner: ScenarioRunner;
  let db: DatabaseClient;
  let config: ConfigSchemaType;
  let issuerFaultController: ServiceControlClient;

  beforeAll(() => {
    config = loadConfig();
    db = new DatabaseClient(config.global.data_dir);

    const controlEndpoint = process.env[SERVICE_CONTROL_ENDPOINT_ENV_VAR];
    if (!controlEndpoint) {
      throw new Error(
        `Missing ${SERVICE_CONTROL_ENDPOINT_ENV_VAR}: run this suite via the itwct CLI (e.g. itwct test issuance), which starts the local service control relay required by the interactive issuance scenarios.`
      );
    }
    issuerFaultController = createServiceControlClient({ endpoint: controlEndpoint });

    const credentialIssuer = config['credential-issuer'].url;
    const federation = config['trust-anchor'].url;
    runner = createProtocolObservedScenarioRunner({
      endpoints: { credentialIssuer, federation },
      eventBridgeFactory: createSqliteScenarioEventBridge({ db }),
      registry: issuanceScenarioRegistry,
      issuerFaultController,
      issuerFaultSpecVersion: '1.4'
    });
  });

  afterAll(async () => {
    await runner.close();
    await issuerFaultController.close();
    db.close();
  });

  describe('Happy path', () => {
    let outcome: ScenarioOutcome;
    let events: ObservedEvent[];
    let authorizationRequest: Awaited<ReturnType<typeof parsePushedAuthorizationRequest>>['authorizationRequest'];
    let clientAttestation: Awaited<ReturnType<typeof parsePushedAuthorizationRequest>>['clientAttestation'];
    let tokenEvent: ObservedEvent;
    let tokenRequestUrl: string;
    let tokenRequestResult: ReturnType<typeof parseAccessTokenRequest>;
    let tokenDpopHeader: DpopJwtHeader;
    let tokenDpopPayload: DpopJwtPayload;
    let nonceEvent: ObservedEvent;
    let credentialEvent: ObservedEvent;
    let credentialRequestUrl: string;
    let credentialRequest: CredentialRequestV1_3;
    let credentialDpopJwt: string;
    let credentialDpopHeader: DpopJwtHeader;
    let credentialDpopPayload: DpopJwtPayload;
    let credentialProofJwt: string;
    let credentialProofHeader: ProofJwtHeaderV1_3;
    let credentialProofPayload: ProofJwtPayload;

    beforeAll(async () => {
      const session = await runner.start(wpCiHappyScenario.id);
      try {
        await session.showInstructions();
        outcome = await session.awaitVerdict();
        events = session.events.all();
      } finally {
        await session.stop();
      }

      // Shared for WP_051/WP_052b/WP_052c/WP_052d: parse the PAR request once
      // here instead of repeating this (network-backed) call in every test.
      const parEvent = events.find((event) => event.name === 'issuer.par.requested');
      if (parEvent) {
        ({ authorizationRequest, clientAttestation } = await parsePushedAuthorizationRequest({
          authorizationRequest: parEvent.diagnostic?.['body'],
          callbacks: { fetch: globalThis.fetch },
          config: new IoWalletSdkConfig({
            itWalletSpecsVersion: ItWalletSpecsVersion.V1_4
          }),
          request: {
            headers: toHeaders(parEvent.diagnostic?.['headers']),
            method: 'POST' as HttpMethod,
            url: `${config['credential-issuer'].url}${parEvent.diagnostic?.['endpoint']}`
          }
        }));
      }

      // Shared for WP_052a/WP_055/WP_055a/WP_055b/WP_055c/WP_055d: parse the
      // Token Request once here instead of repeating this parsing in every test.
      const foundTokenEvent = events.find((event) => event.name === 'issuer.token.requested');
      if (!foundTokenEvent) {
        throw new Error('Missing issuer.token.requested evidence required to assert WP_055 requirements');
      }
      tokenEvent = foundTokenEvent;

      const tokenEndpoint = tokenEvent.diagnostic?.['endpoint'];
      if (typeof tokenEndpoint !== 'string' || tokenEndpoint.length === 0) {
        throw new Error('issuer.token.requested evidence is missing the endpoint diagnostic');
      }
      tokenRequestUrl = `${config['credential-issuer'].url}${tokenEndpoint}`;

      tokenRequestResult = parseAccessTokenRequest({
        accessTokenRequest: tokenEvent.diagnostic?.['body'] as Record<string, unknown>,
        request: {
          headers: toHeaders(tokenEvent.diagnostic?.['headers']),
          method: 'POST' as HttpMethod,
          url: tokenRequestUrl
        }
      });

      ({ header: tokenDpopHeader, payload: tokenDpopPayload } = decodeJwt({
        jwt: tokenRequestResult.dpop.jwt,
        headerSchema: zDpopJwtHeader,
        payloadSchema: zDpopJwtPayload
      }));

      const foundNonceEvent = events.find((event) => event.name === 'issuer.nonce.requested');
      if (!foundNonceEvent) {
        throw new Error('Missing issuer.nonce.requested evidence required to assert WP_056a requirements');
      }
      nonceEvent = foundNonceEvent;

      const foundCredentialEvent = events.find((event) => event.name === 'issuer.credential.requested');
      if (!foundCredentialEvent) {
        throw new Error('Missing issuer.credential.requested evidence required to assert WP_056 requirements');
      }
      credentialEvent = foundCredentialEvent;

      const credentialEndpoint = requiredDiagnosticString(credentialEvent, 'endpoint');
      credentialRequestUrl = `${config['credential-issuer'].url}${credentialEndpoint}`;

      const credentialRequestParseResult = zCredentialRequestV1_3.safeParse(credentialEvent.diagnostic?.['body']);
      if (!credentialRequestParseResult.success) {
        throw new Error(
          `issuer.credential.requested evidence body is not a valid IT-Wallet v1.3/v1.4 Credential Request: ${credentialRequestParseResult.error.message}`
        );
      }
      credentialRequest = credentialRequestParseResult.data;

      const proofJwts = credentialRequest.proofs.jwt;
      if (proofJwts.length !== 1) {
        throw new Error(`Expected exactly one proofs.jwt entry for the standard happy path, found ${proofJwts.length}`);
      }
      credentialProofJwt = proofJwts[0];

      credentialDpopJwt = requiredDiagnosticString(credentialEvent, 'dpopProof');
      ({ header: credentialDpopHeader, payload: credentialDpopPayload } = decodeJwt({
        jwt: credentialDpopJwt,
        headerSchema: zDpopJwtHeader,
        payloadSchema: zDpopJwtPayload
      }));

      ({ header: credentialProofHeader, payload: credentialProofPayload } = decodeJwt({
        jwt: credentialProofJwt,
        headerSchema: zProofJwtHeaderV1_3,
        payloadSchema: zProofJwtPayload
      }));
    }, wpCiHappyScenario.timeouts.vitestTestMs);

    test(
      'WP_018: Wallet Instance periodically and successfully obtains a fresh Wallet Attestation from its Wallet Provider.',
      async () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });
        expect(clientAttestation, 'should parse the client attestation headers from PAR').toBeDefined();
        if (!clientAttestation) {
          throw new Error('PAR request is missing client attestation headers');
        }

        // The Wallet Attestation payload's `cnf.jwk` is mandatory per the SDK's
        // `zWalletAttestationJwtPayloadV1_0`/`V1_3`/`V1_4` schemas.
        const { payload: attestationPayload } = decodeJwt({ jwt: clientAttestation.walletAttestationJwt });
        expect(attestationPayload.iat, 'Wallet Attestation should carry an iat claim').toBeDefined();

        const nowInSeconds = Math.floor(Date.now() / 1000);
        const twentyFourHoursInSeconds = 24 * 60 * 60; // 86400 secondi

        // Verify that iat does not get older than 24 hours
        expect(
          attestationPayload.iat,
          'Wallet Attestation iat should be within the last 24 hours'
        ).toBeGreaterThanOrEqual(nowInSeconds - twentyFourHoursInSeconds);
      },
      wpCiHappyScenario.timeouts.vitestTestMs
    );

    test(
      `WP_046: Wallet Instance successfully uses Federation API endpoints (.well-known/openid-federation, /fetch) to retrieve current metadata and configurations of the Credential Issuer.`,
      async () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });
      },
      wpCiHappyScenario.timeouts.vitestTestMs
    );

    test(
      'WP_051: Wallet Instance successfully requests PID/(Q)EAA from the PID/(Q)EAA Provider using the Authorization Code Flow per OpenID4VCI.',
      () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        expect(authorizationRequest, 'should parse the PAR Authorization Request').toBeDefined();
        expect(authorizationRequest.client_id, 'should include a non-empty client_id').not.toHaveLength(0);
        expect(authorizationRequest.response_type, 'should request the Authorization Code Flow').toBe('code');
      },
      wpCiHappyScenario.timeouts.vitestTestMs
    );

    test(
      'WP_053: Wallet Instance sends an Authorization Request to the Credential Issuer Authorization Endpoint using the received request_uri and client_id.',
      () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        const parEvent = events.find((event) => event.name === 'issuer.par.requested');
        const authorizationEvent = events.find((event) => event.name === 'issuer.authorization.requested');

        expect(parEvent, 'should observe the PAR request evidence').toBeDefined();
        expect(authorizationEvent, 'should observe the Authorization request evidence').toBeDefined();
        if (!parEvent || !authorizationEvent) {
          throw new Error('Missing issuer.par.requested or issuer.authorization.requested evidence');
        }

        expect(authorizationEvent.diagnostic?.['endpoint'], 'should call the Authorization Endpoint').toBe(
          '/authorize'
        );

        const parRequestUri = parEvent.diagnostic?.['requestUri'];
        const authorizationRequestUri = authorizationEvent.diagnostic?.['requestUri'];
        expect(typeof parRequestUri, 'PAR evidence should expose request_uri as a string').toBe('string');
        expect(parRequestUri, 'PAR request_uri should be non-empty').not.toHaveLength(0);
        expect(authorizationRequestUri, 'Authorization request should reuse the PAR request_uri').toBe(parRequestUri);

        expect(authorizationRequest, 'should parse the PAR Authorization Request').toBeDefined();
        const authorizationClientId = authorizationEvent.diagnostic?.['clientId'];
        expect(typeof authorizationClientId, 'Authorization evidence should expose client_id as a string').toBe(
          'string'
        );
        expect(authorizationClientId, 'Authorization client_id should be non-empty').not.toHaveLength(0);
        expect(authorizationClientId, 'Authorization request should reuse the PAR client_id').toBe(
          authorizationRequest.client_id
        );
      },
      wpCiHappyScenario.timeouts.vitestTestMs
    );

    test(
      'WP_052a: Wallet Instance creates the code_verifier following RFC 7636 recommendations for random number generation to prevent brute-force attacks.',
      () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        expect(tokenRequestResult.pkceCodeVerifier, 'should include a PKCE code_verifier').toBeDefined();
        expect(
          tokenRequestResult.pkceCodeVerifier,
          'code_verifier should satisfy RFC 7636 syntax requirements'
        ).toSatisfy(isRfc7636CodeVerifier, 'code_verifier must be an RFC 7636 compliant string');
      },
      wpCiHappyScenario.timeouts.vitestTestMs
    );

    test(
      "WP_052b: Wallet Instance generates the Wallet Attestation PoP JWT and binds it to the same ephemeral public key referenced in the Wallet Attestation's cnf.jwk.",
      async () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });
        expect(clientAttestation, 'should parse the client attestation headers from PAR').toBeDefined();
        if (!clientAttestation) {
          throw new Error('PAR request is missing client attestation headers');
        }

        // The Wallet Attestation payload's `cnf.jwk` is mandatory per the SDK's
        // `zWalletAttestationJwtPayloadV1_0`/`V1_3`/`V1_4` schemas.
        const { payload: attestationPayload } = decodeJwt({ jwt: clientAttestation.walletAttestationJwt });
        const cnfJwk = attestationPayload.cnf?.jwk;
        expect(cnfJwk, 'Wallet Attestation should carry cnf.jwk').toBeDefined();
        if (!cnfJwk) {
          throw new Error('Wallet Attestation payload is missing cnf.jwk');
        }

        const { header: popHeader } = decodeJwtHeader({ jwt: clientAttestation.clientAttestationPopJwt });
        expect(popHeader.typ, 'PoP JWT typ should identify an OAuth client attestation PoP').toBe(
          'oauth-client-attestation-pop+jwt'
        );
        expect(popHeader.alg, 'PoP JWT alg should be allowed by IT-Wallet').toBeOneOf([
          ...IT_WALLET_CLIENT_ATTESTATION_POP_ALLOWED_ALG_VALUES
        ]);

        // Binding assertion: per the IT-Wallet profile, the PoP JWT header does
        // not itself carry a key reference (no `jwk`/`kid` — both are optional
        // per the SDK's `zItWalletClientAttestationPopJwtHeader` and are absent
        // in practice); the verifier is expected to already know the key from
        // the associated Wallet Attestation's `cnf.jwk`. The only way to prove
        // the PoP JWT is bound to that same ephemeral key is to verify its
        // signature directly against it.
        const publicKey = await importJWK(cnfJwk as JWK, popHeader.alg);
        await expect(
          jwtVerify(clientAttestation.clientAttestationPopJwt, publicKey),
          'PoP JWT signature should verify with the Wallet Attestation cnf.jwk'
        ).resolves.toBeDefined();
      },
      wpCiHappyScenario.timeouts.vitestTestMs
    );

    test(
      "WP_052c: Wallet Instance signs the PoP JWT with the ephemeral private key corresponding to the public key in the Wallet Attestation's cnf.jwk.",
      async () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });
        expect(clientAttestation, 'should parse the client attestation headers from PAR').toBeDefined();
        if (!clientAttestation) {
          throw new Error('PAR request is missing client attestation headers');
        }

        const { payload: attestationPayload } = decodeJwt({ jwt: clientAttestation.walletAttestationJwt });
        const cnfJwk = attestationPayload.cnf?.jwk;
        expect(cnfJwk, 'Wallet Attestation should carry cnf.jwk').toBeDefined();
        if (!cnfJwk) {
          throw new Error('Wallet Attestation payload is missing cnf.jwk');
        }

        // `verifyClientAttestationPopJwt` throws (rejects) on any decoding,
        // algorithm, signature, or claim validation failure, so a resolved
        // (defined) result is proof that the PoP JWT signature is valid.
        await expect(
          verifyClientAttestationPopJwt({
            authorizationServer: config['credential-issuer'].url,
            callbacks: { verifyJwt: verifyJwtWithJwk },
            clientAttestationPopJwt: clientAttestation.clientAttestationPopJwt,
            clientAttestationPublicJwk: cnfJwk
          }),
          'PoP JWT should verify against the Wallet Attestation cnf.jwk'
        ).resolves.toBeDefined();
      },
      wpCiHappyScenario.timeouts.vitestTestMs
    );

    test(
      'WP_052d: Wallet Instance embeds correct Digital Credential types in the Request Object using the authorization_details (or scope) parameter.',
      () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });
        expect(authorizationRequest, 'should parse the PAR Authorization Request').toBeDefined();

        // Matches the credential_configuration_ids requested in createCredentialOfferUri().
        const expectedCredentialConfigurationId = 'dc_sd_jwt_EuropeanDisabilityCard';

        const hasMatchingAuthorizationDetail = authorizationRequest.authorization_details?.some(
          (detail) =>
            detail.type === 'openid_credential' &&
            detail.credential_configuration_id === expectedCredentialConfigurationId
        );
        const hasMatchingScope = authorizationRequest.scope?.split(/\s+/).includes(expectedCredentialConfigurationId);

        expect(
          hasMatchingAuthorizationDetail || hasMatchingScope,
          'should request the expected credential configuration via authorization_details or scope'
        ).toBe(true);
      },
      wpCiHappyScenario.timeouts.vitestTestMs
    );

    test(
      'WP_055: Wallet Instance sends the Token Request to the Credential Issuer Token Endpoint using the authorization_code grant with the code, redirect_uri and PKCE code_verifier.',
      () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        expect(tokenEvent.diagnostic?.['endpoint'], 'should call the Token Endpoint').toBe('/token');

        const tokenRequestHeaders = toHeaders(tokenEvent.diagnostic?.['headers']);
        const contentType = tokenRequestHeaders.get('content-type');
        expect(contentType, 'Token Request should include a Content-Type header').not.toBeNull();
        expect(contentType?.toLowerCase(), 'Token Request should use form-urlencoded content').toContain(
          'application/x-www-form-urlencoded'
        );

        expect(tokenRequestResult.grant.grantType, 'parsed grant should be authorization_code').toBe(
          'authorization_code'
        );
        if (tokenRequestResult.grant.grantType !== 'authorization_code') {
          throw new Error('Expected the Token Request to use the authorization_code grant');
        }
        expect(tokenRequestResult.grant.code, 'Token Request should include a non-empty code').not.toHaveLength(0);

        const { accessTokenRequest } = tokenRequestResult;
        expect(accessTokenRequest.grant_type, 'request body grant_type should be authorization_code').toBe(
          'authorization_code'
        );
        if (accessTokenRequest.grant_type !== 'authorization_code') {
          throw new Error('Expected the Token Request body to use the authorization_code grant');
        }

        // The redirect_uri from the Token Request must match the one carried
        // in the PAR Request Object, proving the Wallet Instance presents the
        // same redirection endpoint it registered during authorization.
        expect(authorizationRequest, 'should parse the PAR Authorization Request').toBeDefined();
        expect(accessTokenRequest.redirect_uri, 'Token redirect_uri should match the PAR redirect_uri').toBe(
          authorizationRequest.redirect_uri
        );

        expect(tokenRequestResult.pkceCodeVerifier, 'Token Request should include a PKCE code_verifier').toBeDefined();
        expect(tokenRequestResult.pkceCodeVerifier, 'PKCE code_verifier should be non-empty').not.toHaveLength(0);
      },
      wpCiHappyScenario.timeouts.vitestTestMs
    );

    test(
      'WP_055a: Wallet Instance authenticates the Token Request with the DPoP proof, the Wallet Attestation and the Wallet Instance PoP, sent as three distinct JWT headers.',
      () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        expect(tokenRequestResult.dpop.jwt, 'Token Request should include a DPoP JWT').not.toHaveLength(0);
        expect(
          tokenRequestResult.clientAttestation.walletAttestationJwt,
          'Token Request should include the Wallet Attestation JWT'
        ).not.toHaveLength(0);
        expect(
          tokenRequestResult.clientAttestation.clientAttestationPopJwt,
          'Token Request should include the Wallet Instance PoP JWT'
        ).not.toHaveLength(0);

        const { header: dpopHeader } = decodeJwtHeader({
          jwt: tokenRequestResult.dpop.jwt,
          headerSchema: zDpopJwtHeader
        });
        expect(dpopHeader.typ, 'DPoP JWT typ should be dpop+jwt').toBe('dpop+jwt');

        // Confirms the Wallet Attestation header decodes as a well-formed JWT;
        // its `typ` is version-dependent (see zWalletAttestationJwtHeaderV1_0/
        // V1_3/V1_4 in the SDK) and is intentionally not pinned to one value here.
        expect(
          () => decodeJwtHeader({ jwt: tokenRequestResult.clientAttestation.walletAttestationJwt }),
          'Wallet Attestation header should decode as a well-formed JWT'
        ).not.toThrow();

        const { header: popHeader } = decodeJwtHeader({
          jwt: tokenRequestResult.clientAttestation.clientAttestationPopJwt,
          headerSchema: zItWalletClientAttestationPopJwtHeader
        });
        expect(popHeader.typ, 'PoP JWT typ should identify an OAuth client attestation PoP').toBe(
          'oauth-client-attestation-pop+jwt'
        );
      },
      wpCiHappyScenario.timeouts.vitestTestMs
    );

    test(
      'WP_055b: Wallet Instance generates a fresh DPoP key for the Token Request, with a proof JWT conforming to RFC 9449 and bound to the Token Endpoint.',
      () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        const { header: dpopHeader, payload: dpopPayload } = decodeJwt({
          jwt: tokenRequestResult.dpop.jwt,
          headerSchema: zDpopJwtHeader,
          payloadSchema: zDpopJwtPayload
        });

        expect(dpopHeader.typ, 'DPoP JWT typ should be dpop+jwt').toBe('dpop+jwt');
        expect(dpopHeader.alg, 'DPoP JWT alg should not be none').not.toBe('none');

        expect(dpopHeader.jwk, 'DPoP JWT header should include a public JWK').toBeDefined();
        expect(dpopHeader.jwk.d, 'DPoP JWT header should not expose private key material').toBeUndefined();

        expect(dpopPayload.htm, 'DPoP proof should be bound to POST').toBe('POST');
        expect(dpopPayload.htu, 'DPoP proof should be bound to the Token Endpoint URL').toBe(
          htuFromRequestUrl(tokenRequestUrl)
        );

        expect(dpopPayload.iat, 'DPoP proof should carry a numeric iat').toBeTypeOf('number');
        const iatMs = dpopPayload.iat * 1000;
        const eventMs = new Date(tokenEvent.timestamp).getTime();
        expect(
          Math.abs(eventMs - iatMs),
          'DPoP proof iat should be fresh relative to the Token Request event'
        ).toBeLessThanOrEqual(DPOP_IAT_FRESHNESS_TOLERANCE_SECONDS * 1000);

        expect(dpopPayload.jti, 'DPoP proof should carry a non-empty jti').not.toHaveLength(0);

        // Reuse of the PAR DPoP proof/key for the Token Request would defeat
        // the purpose of per-request proof-of-possession, so both the `jti`
        // and the JWK thumbprint (RFC 7638) must differ from the PAR DPoP.
        expect(
          clientAttestation,
          'PAR client attestation data should be present to compare key rotation'
        ).toBeDefined();
        if (!clientAttestation) {
          throw new Error('Missing DPoP proof from the PAR request needed to assert key rotation');
        }
        const { payload: parDpopPayload } = decodeJwt({
          jwt: clientAttestation?.clientAttestationPopJwt,
          headerSchema: zItWalletClientAttestationPopJwtHeader,
          payloadSchema: zItWalletClientAttestationPopJwtPayload
        });
        expect(dpopPayload.jti, 'Token DPoP jti should differ from the PAR PoP jti').not.toBe(parDpopPayload.jti);

        expect(
          jwtVerify(clientAttestation?.clientAttestationPopJwt, dpopHeader.jwk),
          'Token DPoP public key should not verify the PAR PoP JWT'
        ).rejects.toThrow();
      },
      wpCiHappyScenario.timeouts.vitestTestMs
    );

    test(
      'WP_055c: Wallet Instance signs the Token Request DPoP proof with the private key matching the public JWK declared in the DPoP proof header.',
      async () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        const { header: dpopHeader } = decodeJwtHeader({
          jwt: tokenRequestResult.dpop.jwt,
          headerSchema: zDpopJwtHeader
        });

        // `jwtVerify` throws (rejects) on any signature mismatch, so a
        // resolved (defined) result is proof the DPoP proof was signed by the
        // private key corresponding to the declared public JWK.
        const publicKey = await importJWK(dpopHeader.jwk as JWK, dpopHeader.alg);
        await expect(
          jwtVerify(tokenRequestResult.dpop.jwt, publicKey),
          'DPoP proof signature should verify with the declared public JWK'
        ).resolves.toBeDefined();
      },
      wpCiHappyScenario.timeouts.vitestTestMs
    );

    test(
      'WP_055d: Wallet Instance binds the Token Request to the Wallet Instance ephemeral key by signing the Wallet Instance PoP with the private key matching the Wallet Attestation cnf.jwk.',
      async () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        const { payload: attestationPayload } = decodeJwt({
          jwt: tokenRequestResult.clientAttestation.walletAttestationJwt
        });
        const cnfJwk = attestationPayload.cnf?.jwk;
        expect(cnfJwk, 'Token Request Wallet Attestation should carry cnf.jwk').toBeDefined();
        if (!cnfJwk) {
          throw new Error('Token Request Wallet Attestation payload is missing cnf.jwk');
        }

        const { header: popHeader, payload: popPayload } = decodeJwt({
          jwt: tokenRequestResult.clientAttestation.clientAttestationPopJwt,
          headerSchema: zItWalletClientAttestationPopJwtHeader,
          payloadSchema: zItWalletClientAttestationPopJwtPayload
        });
        expect(popHeader.typ, 'PoP JWT typ should identify an OAuth client attestation PoP').toBe(
          'oauth-client-attestation-pop+jwt'
        );
        expect(popHeader.alg, 'PoP JWT alg should be allowed by IT-Wallet').toBeOneOf([
          ...IT_WALLET_CLIENT_ATTESTATION_POP_ALLOWED_ALG_VALUES
        ]);

        expect(popPayload.aud, 'PoP JWT aud should target the Credential Issuer').toBe(config['credential-issuer'].url);
        expect(popPayload.iat, 'PoP JWT should carry a numeric iat').toBeTypeOf('number');
        expect(popPayload.iss, 'PoP JWT should carry a non-empty iss').not.toHaveLength(0);
        expect(popPayload.jti, 'PoP JWT should carry a non-empty jti').not.toHaveLength(0);

        // `verifyClientAttestationPopJwt` throws (rejects) on any decoding,
        // algorithm, signature, or claim validation failure, so a resolved
        // (defined) result is proof the Wallet Instance PoP for the Token
        // Request is bound to the Wallet Attestation's cnf.jwk.
        await expect(
          verifyClientAttestationPopJwt({
            authorizationServer: config['credential-issuer'].url,
            callbacks: { verifyJwt: verifyJwtWithJwk },
            clientAttestationPopJwt: tokenRequestResult.clientAttestation.clientAttestationPopJwt,
            clientAttestationPublicJwk: cnfJwk
          }),
          'Token Request PoP JWT should verify against the Wallet Attestation cnf.jwk'
        ).resolves.toBeDefined();
      },
      wpCiHappyScenario.timeouts.vitestTestMs
    );

    test(
      'WP_056: Wallet Instance sends a complete Credential Request with DPoP Access Token authentication, the expected credential identifier, and a valid proof of possession.',
      async () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        expect(credentialEvent.diagnostic?.['endpoint'], 'should call the Credential Endpoint').toBe('/credential');
        expect(credentialEvent.diagnostic?.['method'], 'Credential Request should use POST').toBe('POST');

        const contentType = requiredDiagnosticString(credentialEvent, 'contentType');
        expect(contentType.toLowerCase(), 'Credential Request should use JSON content').toContain('application/json');

        expect(
          credentialEvent.diagnostic?.['authorizationScheme'],
          'Credential Request should use DPoP authorization'
        ).toBe('DPoP');
        expect(
          requiredDiagnosticString(credentialEvent, 'accessTokenSha256'),
          'Credential Request evidence should include the access token hash'
        ).not.toHaveLength(0);
        expect(credentialDpopJwt, 'Credential Request should include a DPoP proof').not.toHaveLength(0);

        expect(
          credentialRequest.credential_identifier,
          'Credential Request should request the expected credential identifier'
        ).toBe('dc_sd_jwt_EuropeanDisabilityCard');
        expect(credentialProofJwt, 'Credential Request should include a proof JWT').not.toHaveLength(0);

        const publicKey = await importJWK(credentialProofHeader.jwk as JWK, credentialProofHeader.alg);
        await expect(
          jwtVerify(credentialProofJwt, publicKey),
          'Credential proof JWT signature should verify with the declared public JWK'
        ).resolves.toBeDefined();
      },
      wpCiHappyScenario.timeouts.vitestTestMs
    );

    test(
      'WP_056a: Wallet Instance obtains a fresh Nonce Endpoint c_nonce and uses it in the Credential proof JWT.',
      () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        expect(nonceEvent.diagnostic?.['endpoint'], 'should call the Nonce Endpoint').toBe('/nonce');
        expect(nonceEvent.diagnostic?.['method'], 'Nonce Request should use POST').toBe('POST');
        expect(nonceEvent.monotonicMs, 'Nonce Request should happen before the Credential Request').toBeLessThan(
          credentialEvent.monotonicMs
        );

        const cNonceSha256 = requiredDiagnosticString(nonceEvent, 'cNonceSha256');
        expect(cNonceSha256, 'Nonce evidence should include a non-empty c_nonce hash').not.toHaveLength(0);

        expect(credentialProofPayload.nonce, 'Credential proof should carry a non-empty nonce').not.toHaveLength(0);
        expect(
          sha256Base64Url(credentialProofPayload.nonce),
          'Credential proof nonce should match the Nonce Endpoint c_nonce'
        ).toBe(cNonceSha256);

        expect(credentialProofPayload.iat, 'Credential proof should carry a numeric iat').toBeTypeOf('number');
        const iatMs = credentialProofPayload.iat * 1000;
        const eventMs = new Date(credentialEvent.timestamp).getTime();
        expect(
          Math.abs(eventMs - iatMs),
          'Credential proof iat should be fresh relative to the Credential Request event'
        ).toBeLessThanOrEqual(DPOP_IAT_FRESHNESS_TOLERANCE_SECONDS * 1000);
      },
      wpCiHappyScenario.timeouts.vitestTestMs
    );

    test(
      'WP_056b: Wallet Instance sends a fresh Credential Request DPoP proof bound to the Credential Endpoint, reusing the Token Request DPoP key and carrying the RFC 9449 ath claim.',
      async () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        expect(credentialDpopHeader.typ, 'Credential DPoP JWT typ should be dpop+jwt').toBe('dpop+jwt');
        expect(credentialDpopHeader.alg, 'Credential DPoP JWT alg should not be none').not.toBe('none');
        expect(credentialDpopHeader.jwk, 'Credential DPoP JWT header should include a public JWK').toBeDefined();
        expect(credentialDpopHeader.jwk.kty, 'Credential DPoP key should not be symmetric').not.toBe('oct');
        expect(
          credentialDpopHeader.jwk.d,
          'Credential DPoP JWT header should not expose private key material'
        ).toBeUndefined();

        const publicKey = await importJWK(credentialDpopHeader.jwk as JWK, credentialDpopHeader.alg);
        await expect(
          jwtVerify(credentialDpopJwt, publicKey),
          'Credential DPoP proof signature should verify with the declared public JWK'
        ).resolves.toBeDefined();

        expect(credentialDpopPayload.htm, 'Credential DPoP proof should be bound to POST').toBe('POST');
        expect(credentialDpopPayload.htu, 'Credential DPoP proof should be bound to the Credential Endpoint URL').toBe(
          htuFromRequestUrl(credentialRequestUrl)
        );

        expect(credentialDpopPayload.iat, 'Credential DPoP proof should carry a numeric iat').toBeTypeOf('number');
        const iatMs = credentialDpopPayload.iat * 1000;
        const eventMs = new Date(credentialEvent.timestamp).getTime();
        expect(
          Math.abs(eventMs - iatMs),
          'Credential DPoP proof iat should be fresh relative to the Credential Request event'
        ).toBeLessThanOrEqual(DPOP_IAT_FRESHNESS_TOLERANCE_SECONDS * 1000);

        expect(credentialDpopPayload.jti, 'Credential DPoP proof should carry a non-empty jti').not.toHaveLength(0);
        expect(credentialDpopPayload.jti, 'Credential DPoP jti should differ from the Token DPoP jti').not.toBe(
          tokenDpopPayload.jti
        );

        await expect(
          calculateJwkThumbprint(credentialDpopHeader.jwk as JWK),
          'Credential DPoP key should match the Token Request DPoP key'
        ).resolves.toBe(await calculateJwkThumbprint(tokenDpopHeader.jwk as JWK));

        expect(credentialDpopPayload.ath, 'Credential DPoP ath should match the access token hash').toBe(
          requiredDiagnosticString(credentialEvent, 'accessTokenSha256')
        );
      },
      wpCiHappyScenario.timeouts.vitestTestMs
    );
  });

  describe('WP_046a', () => {
    let outcome: ScenarioOutcome;
    let events: ObservedEvent[];

    beforeAll(async () => {
      const session = await runner.start(wp046aScenario.id);
      try {
        await session.showInstructions();
        outcome = await session.awaitVerdict();
        events = session.events.all();
      } finally {
        // Deactivating the fault (last step of `session.stop()`) must happen
        // even if the assertions below fail, so later scenarios never observe
        // leaked fault state.
        await session.stop();
      }
    }, wp046aScenario.timeouts.vitestTestMs);

    test(
      'WP_046a: Wallet Instance rejects a Credential Issuer whose Entity Configuration authority_hints do not include the expected Trust Anchor.',
      () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        const entityConfigurationEvent = events.find((event) => event.name === 'issuer.entity_configuration.requested');
        const faultAppliedEvent = events.find((event) => event.name === 'issuer.fault.applied');

        expect(
          entityConfigurationEvent,
          'Wallet must request the Credential Issuer Entity Configuration before this scenario can pass'
        ).toBeDefined();
        expect(
          faultAppliedEvent,
          'The invalid-trust-anchor fault must have been applied while serving the Entity Configuration'
        ).toBeDefined();
        expect(faultAppliedEvent?.diagnostic?.['faultProfileType']).toBe('invalid-trust-anchor');

        expect(
          events.find((event) => event.name === 'federation.fetch.requested'),
          'Wallet must not resolve the configured Trust Anchor subordinate statement for the mutated authority_hints'
        ).toBeUndefined();
        expect(
          events.find((event) => event.name === 'issuer.par.requested'),
          'Wallet must not continue to PAR after failing to validate the invalid Trust Anchor'
        ).toBeUndefined();
      },
      wp046aScenario.timeouts.vitestTestMs
    );

    test('Cleanup: deactivating the invalid-trust-anchor fault restores the configured Trust Anchor for subsequent scenarios.', async () => {
      // Local services (credential-issuer, trust-anchor, relying-party) use ephemeral,
      // self-signed certificates (see @itw-conformance-tool/crypto's createHttpsOptions),
      // so a plain global `fetch()` fails TLS verification. Use `httpsRequest` with
      // `rejectUnauthorized: false`, matching the convention used elsewhere for these hosts.
      const discoveryUrl = new URL('/.well-known/openid-federation', config['credential-issuer'].url);
      const response = await httpsRequest({
        method: 'GET',
        hostname: discoveryUrl.hostname,
        path: discoveryUrl.pathname,
        port: discoveryUrl.port,
        protocol: discoveryUrl.protocol,
        rejectUnauthorized: false,
        signal: AbortSignal.timeout(10_000)
      });

      if (response.statusCode !== 200) {
        throw new Error(
          `Unable to fetch Credential Issuer entity configuration (${response.statusCode ?? 'unknown'}): ${response.body}`
        );
      }

      const claims = decodeEntityConfiguration(response.body);

      expect(
        claims.authority_hints,
        'The Credential Issuer must serve the configured Trust Anchor again once the fault is deactivated'
      ).toEqual([trimTrailingSlash(config['trust-anchor'].url)]);
    }, 10_000);
  });

  // Unlike WP_046a's stateless Entity Configuration endpoint, /code/jwt
  // requires a live Authorization request_uri from a fresh PAR/authorize
  // round-trip, so it cannot be probed out-of-band with a plain HTTP request
  // after the scenario ends. Instead, cleanup is verified with a
  // control-channel probe (see "Authorization Response fault cleanup" below):
  // if any variant leaked its active fault, activating a fresh profile for an
  // unrelated scenario ID would be rejected by the Credential Issuer's
  // single-active-fault store.
  describe('WP_054 (missing code)', () => {
    let outcome: ScenarioOutcome;
    let events: ObservedEvent[];

    beforeAll(async () => {
      const session = await runner.start(wp054MissingCodeScenario.id);
      try {
        await session.showInstructions();
        outcome = await session.awaitVerdict();
        events = session.events.all();
      } finally {
        // Deactivating the fault (last step of `session.stop()`) must happen
        // even if the assertions below fail, so later scenarios never observe
        // leaked fault state.
        await session.stop();
      }
    }, wp054MissingCodeScenario.timeouts.vitestTestMs);

    test(
      "WP_054: Wallet Instance rejects an Authorization Response missing 'code'.",
      () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        const authorizationEvent = events.find((event) => event.name === 'issuer.authorization.requested');
        const faultAppliedEvent = events.find((event) => event.name === 'issuer.fault.applied');

        expect(
          authorizationEvent,
          'Wallet must request the Credential Issuer Authorization Endpoint before this scenario can pass'
        ).toBeDefined();
        expect(
          faultAppliedEvent,
          'The authorization-response-missing-claim fault must have been applied while serving /code/jwt'
        ).toBeDefined();
        expect(faultAppliedEvent?.diagnostic?.['faultProfileType']).toBe('authorization-response-missing-claim');
        expect(faultAppliedEvent?.diagnostic?.['omittedClaim']).toBe('code');

        expect(
          events.find((event) => event.name === 'issuer.token.requested'),
          "Wallet must not continue to the Token Endpoint after an Authorization Response missing 'code'"
        ).toBeUndefined();
        expect(
          events.find((event) => event.name === 'issuer.nonce.requested'),
          'Wallet must not continue to the Nonce Endpoint after a malformed Authorization Response'
        ).toBeUndefined();
        expect(
          events.find((event) => event.name === 'issuer.credential.requested'),
          'Wallet must not continue to the Credential Endpoint after a malformed Authorization Response'
        ).toBeUndefined();
      },
      wp054MissingCodeScenario.timeouts.vitestTestMs
    );
  });

  describe('WP_054a (invalid state)', () => {
    let outcome: ScenarioOutcome;
    let events: ObservedEvent[];

    beforeAll(async () => {
      const session = await runner.start(wp054aInvalidStateScenario.id);
      try {
        await session.showInstructions();
        outcome = await session.awaitVerdict();
        events = session.events.all();
      } finally {
        // Deactivating the fault (last step of `session.stop()`) must happen
        // even if the assertions below fail, so later scenarios never observe
        // leaked fault state.
        await session.stop();
      }
    }, wp054aInvalidStateScenario.timeouts.vitestTestMs);

    test(
      'WP_054a: Wallet Instance rejects an Authorization Response with mismatched state.',
      () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        const authorizationEvent = events.find((event) => event.name === 'issuer.authorization.requested');
        const faultAppliedEvent = events.find((event) => event.name === 'issuer.fault.applied');

        expect(
          authorizationEvent,
          'Wallet must request the Credential Issuer Authorization Endpoint before this scenario can pass'
        ).toBeDefined();
        expect(
          faultAppliedEvent,
          'The authorization-response-invalid-state fault must have been applied while serving /code/jwt'
        ).toBeDefined();
        expect(faultAppliedEvent?.diagnostic?.['faultProfileType']).toBe('authorization-response-invalid-state');
        expect(faultAppliedEvent?.diagnostic?.['mutatedClaim']).toBe('state');

        expect(
          events.find((event) => event.name === 'issuer.token.requested'),
          'Wallet must not continue to the Token Endpoint after an Authorization Response with mismatched state'
        ).toBeUndefined();
        expect(
          events.find((event) => event.name === 'issuer.nonce.requested'),
          'Wallet must not continue to the Nonce Endpoint after a mismatched Authorization Response state'
        ).toBeUndefined();
        expect(
          events.find((event) => event.name === 'issuer.credential.requested'),
          'Wallet must not continue to the Credential Endpoint after a mismatched Authorization Response state'
        ).toBeUndefined();
      },
      wp054aInvalidStateScenario.timeouts.vitestTestMs
    );
  });

  describe('WP_054b (invalid issuer)', () => {
    let outcome: ScenarioOutcome;
    let events: ObservedEvent[];

    beforeAll(async () => {
      const session = await runner.start(wp054bInvalidIssuerScenario.id);
      try {
        await session.showInstructions();
        outcome = await session.awaitVerdict();
        events = session.events.all();
      } finally {
        // Deactivating the fault (last step of `session.stop()`) must happen
        // even if the assertions below fail, so later scenarios never observe
        // leaked fault state.
        await session.stop();
      }
    }, wp054bInvalidIssuerScenario.timeouts.vitestTestMs);

    test(
      'WP_054b: Wallet Instance rejects an Authorization Response with mismatched issuer.',
      () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        const authorizationEvent = events.find((event) => event.name === 'issuer.authorization.requested');
        const faultAppliedEvent = events.find((event) => event.name === 'issuer.fault.applied');

        expect(
          authorizationEvent,
          'Wallet must request the Credential Issuer Authorization Endpoint before this scenario can pass'
        ).toBeDefined();
        expect(
          faultAppliedEvent,
          'The authorization-response-invalid-issuer fault must have been applied while serving /code/jwt'
        ).toBeDefined();
        expect(faultAppliedEvent?.diagnostic?.['faultProfileType']).toBe('authorization-response-invalid-issuer');
        expect(faultAppliedEvent?.diagnostic?.['mutatedClaim']).toBe('iss');

        expect(
          events.find((event) => event.name === 'issuer.token.requested'),
          'Wallet must not continue to the Token Endpoint after an Authorization Response with mismatched issuer'
        ).toBeUndefined();
        expect(
          events.find((event) => event.name === 'issuer.nonce.requested'),
          'Wallet must not continue to the Nonce Endpoint after a mismatched Authorization Response issuer'
        ).toBeUndefined();
        expect(
          events.find((event) => event.name === 'issuer.credential.requested'),
          'Wallet must not continue to the Credential Endpoint after a mismatched Authorization Response issuer'
        ).toBeUndefined();
      },
      wp054bInvalidIssuerScenario.timeouts.vitestTestMs
    );
  });

  describe('Authorization Response fault cleanup', () => {
    test('authorization-response faults are deactivated and a later scenario can activate a fresh profile', async () => {
      // Each `session.stop()` above already deactivates its own fault, but if
      // any Authorization Response negative scenario had leaked its active
      // fault, this activation (for an unrelated scenario ID) would be
      // rejected with FAULT_ALREADY_ACTIVE by the Credential Issuer's
      // single-active-fault store. Successfully activating and deactivating
      // here is a control-channel probe proving cleanup worked and a later
      // scenario can still activate a fresh implemented profile.
      const probeScenarioId = `wp054-cleanup-probe-${randomUUID()}`;

      await issuerFaultController.activateIssuerFault({
        scenarioId: probeScenarioId,
        specVersion: '1.4',
        profile: { type: 'authorization-response-invalid-state' }
      });

      await issuerFaultController.deactivateIssuerFault({ scenarioId: probeScenarioId });
    }, 10_000);
  });

  describe('WP_Unsupported_Credential_Offer', () => {
    let outcome: ScenarioOutcome;
    let events: ObservedEvent[];
    let credentialOfferUri: string;

    beforeAll(async () => {
      const session = await runner.start(wpUnsupportedCredentialOfferScenario.id);

      try {
        await session.showInstructions();
        outcome = await session.awaitVerdict();
        events = session.events.all();
        credentialOfferUri = session.stimulus.type === 'credential-offer' ? session.stimulus.uri : '';
      } finally {
        // Deactivating the fault (last step of `session.stop()`) must happen
        // even if the assertions below fail, so later scenarios never observe
        // leaked fault state.
        await session.stop();
      }
    }, wpUnsupportedCredentialOfferScenario.timeouts.vitestTestMs);

    test(
      'WP_050b: Wallet Instance rejects a Credential Offer whose credential_configuration_ids entry is not published in the Credential Issuer metadata.',
      () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        const entityConfigurationEvent = events.find((event) => event.name === 'issuer.entity_configuration.requested');
        const credentialOfferGeneratedEvent = events.find((event) => event.name === 'credential_offer.generated');

        expect(
          entityConfigurationEvent,
          'Wallet must request the Credential Issuer Entity Configuration before this scenario can pass'
        ).toBeDefined();

        // unsupported-credential-offer's application point is the runner
        // itself (the offer is built and shown by createStimulus, not served
        // by a Credential Issuer HTTP route), so the safe local evidence that
        // the fault was applied lives on credential_offer.generated rather
        // than on an issuer.fault.applied HTTP event.
        expect(
          credentialOfferGeneratedEvent,
          'The runner must record that the unsupported-credential-offer fault was applied to the shown stimulus'
        ).toBeDefined();
        expect(credentialOfferGeneratedEvent?.diagnostic?.['faultProfileType']).toBe('unsupported-credential-offer');
        expect(credentialOfferGeneratedEvent?.diagnostic?.['credentialConfigurationId']).toBe(
          WP_UNSUPPORTED_CREDENTIAL_CONFIGURATION_ID
        );
        expect(credentialOfferGeneratedEvent?.diagnostic?.['outcome']).toBe('applied');

        // Decode the credential offer actually shown to the wallet and prove
        // it carries the reserved, unsupported id -- not the nominal one --
        // so a genuine conformance failure would mean the wallet accepted an
        // offer it could not have found in credential_configurations_supported.
        const credentialOfferParam = new URL(credentialOfferUri).searchParams.get('credential_offer');
        expect(
          credentialOfferParam,
          'openid-credential-offer:// URI must carry a credential_offer payload'
        ).not.toBeNull();
        const offerPayload = JSON.parse(credentialOfferParam ?? '{}') as { credential_configuration_ids?: string[] };
        expect(offerPayload.credential_configuration_ids).toEqual([WP_UNSUPPORTED_CREDENTIAL_CONFIGURATION_ID]);

        expect(
          events.find((event) => event.name === 'issuer.par.requested'),
          'Wallet must not continue to PAR after determining the requested credential_configuration_id is unsupported'
        ).toBeUndefined();
        expect(events.find((event) => event.name === 'issuer.authorization.requested')).toBeUndefined();
        expect(events.find((event) => event.name === 'issuer.token.requested')).toBeUndefined();
        expect(events.find((event) => event.name === 'issuer.nonce.requested')).toBeUndefined();
        expect(events.find((event) => event.name === 'issuer.credential.requested')).toBeUndefined();
      },
      wpUnsupportedCredentialOfferScenario.timeouts.vitestTestMs
    );

    test(
      'WP_048: Wallet Instance requests the Credential Issuer Entity Configuration to parse the Credential Offer parameters.',
      () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        const entityConfigurationEvent = events.find((event) => event.name === 'issuer.entity_configuration.requested');

        expect(
          entityConfigurationEvent,
          'Wallet must request the Credential Issuer Entity Configuration before this scenario can pass'
        ).toBeDefined();
      },
      wpUnsupportedCredentialOfferScenario.timeouts.vitestTestMs
    );

    test(
      'WP_050: Wallet Instance rejects a Credential Offer whose credential_configuration_ids entry is not published in the Credential Issuer metadata.',
      () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        const entityConfigurationEvent = events.find((event) => event.name === 'issuer.entity_configuration.requested');
        const credentialOfferGeneratedEvent = events.find((event) => event.name === 'credential_offer.generated');

        expect(
          entityConfigurationEvent,
          'Wallet must request the Credential Issuer Entity Configuration before this scenario can pass'
        ).toBeDefined();

        // unsupported-credential-offer's application point is the runner
        // itself (the offer is built and shown by createStimulus, not served
        // by a Credential Issuer HTTP route), so the safe local evidence that
        // the fault was applied lives on credential_offer.generated rather
        // than on an issuer.fault.applied HTTP event.
        expect(
          credentialOfferGeneratedEvent,
          'The runner must record that the unsupported-credential-offer fault was applied to the shown stimulus'
        ).toBeDefined();
        expect(credentialOfferGeneratedEvent?.diagnostic?.['faultProfileType']).toBe('unsupported-credential-offer');
        expect(credentialOfferGeneratedEvent?.diagnostic?.['credentialConfigurationId']).toBe(
          WP_UNSUPPORTED_CREDENTIAL_CONFIGURATION_ID
        );
        expect(credentialOfferGeneratedEvent?.diagnostic?.['outcome']).toBe('applied');

        // Decode the credential offer actually shown to the wallet and prove
        // it carries the reserved, unsupported id -- not the nominal one --
        // so a genuine conformance failure would mean the wallet accepted an
        // offer it could not have found in credential_configurations_supported.
        const credentialOfferParam = new URL(credentialOfferUri).searchParams.get('credential_offer');
        expect(
          credentialOfferParam,
          'openid-credential-offer:// URI must carry a credential_offer payload'
        ).not.toBeNull();
        const offerPayload = JSON.parse(credentialOfferParam ?? '{}') as { credential_configuration_ids?: string[] };
        expect(offerPayload.credential_configuration_ids).toEqual([WP_UNSUPPORTED_CREDENTIAL_CONFIGURATION_ID]);

        expect(
          events.find((event) => event.name === 'issuer.par.requested'),
          'Wallet must not continue to PAR after determining the requested credential_configuration_id is unsupported'
        ).toBeUndefined();
        expect(events.find((event) => event.name === 'issuer.authorization.requested')).toBeUndefined();
        expect(events.find((event) => event.name === 'issuer.token.requested')).toBeUndefined();
        expect(events.find((event) => event.name === 'issuer.nonce.requested')).toBeUndefined();
        expect(events.find((event) => event.name === 'issuer.credential.requested')).toBeUndefined();
      },
      wpUnsupportedCredentialOfferScenario.timeouts.vitestTestMs
    );

    test('Cleanup: deactivating the unsupported-credential-offer fault does not leave the shared fault store locked for later scenarios.', async () => {
      // Unlike invalid-trust-anchor, this fault is applied entirely by the
      // runner when building the credential offer (helpers/issuance.ts),
      // not by a live Credential Issuer HTTP response, so there is no
      // endpoint to re-fetch here. Instead, prove that the session.stop()
      // above released the Credential Issuer's single-active-fault store
      // (apps/itw-credential-issuer/src/domain/faults/issuer-fault-store.ts)
      // by activating and deactivating a fresh fault under a new
      // scenarioId: if deactivation above had leaked, this activation would
      // be rejected with FAULT_ALREADY_ACTIVE.
      const probeScenarioId = randomUUID();
      await issuerFaultController.activateIssuerFault({
        scenarioId: probeScenarioId,
        specVersion: '1.4',
        profile: { type: 'invalid-trust-anchor' }
      });
      await issuerFaultController.deactivateIssuerFault({ scenarioId: probeScenarioId });
    }, 10_000);
  });

  describe('WP_Credential_Response_Claims_Missed', () => {
    let outcome: ScenarioOutcome;
    let events: ObservedEvent[];

    beforeAll(async () => {
      const session = await runner.start(wp059Scenario.id);

      try {
        await session.showInstructions();
        outcome = await session.awaitVerdict();
        events = session.events.all();
      } finally {
        // Deactivating the fault (last step of `session.stop()`) must happen
        // even if the assertions below fail, so later scenarios never observe
        // leaked fault state.
        await session.stop();
      }
    }, wp059Scenario.timeouts.vitestTestMs);

    test(
      'WP_059: Wallet Instance rejects an immediate Credential Response missing the required credentials parameter.',
      () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        const credentialEvent = events.find((event) => event.name === 'issuer.credential.requested');
        const faultAppliedEvent = events.find((event) => event.name === 'issuer.fault.applied');

        expect(
          credentialEvent,
          'Wallet must send the Credential Request through the full happy-path flow before this scenario can pass'
        ).toBeDefined();
        expect(
          faultAppliedEvent,
          'The edc-missing-required-claims fault must have been applied while serving the Credential Response'
        ).toBeDefined();
        expect(faultAppliedEvent?.diagnostic?.['faultProfileType']).toBe('edc-missing-required-claims');
        expect(faultAppliedEvent?.diagnostic?.['endpoint']).toBe('/credential');
        expect(
          faultAppliedEvent?.diagnostic?.['omittedParameters'],
          'The fault must report credentials as the omitted parameter'
        ).toEqual(['credentials']);
        expect(
          faultAppliedEvent?.diagnostic?.['statusCode'],
          'The malformed immediate response must still be served as HTTP 200'
        ).toBe(200);
        expect(faultAppliedEvent?.diagnostic?.['contentType']).toBe('application/json');
      },
      wp059Scenario.timeouts.vitestTestMs
    );
  });

  describe.each([
    {
      scenario: wp060TypeMismatchScenario,
      label: 'type-mismatch',
      testTitle: "WP_060: Wallet Instance rejects a Digital Credential whose 'vct' does not match the requested type."
    }
  ])('WP_060 ($label)', ({ scenario, label, testTitle }) => {
    let outcome: ScenarioOutcome;
    let events: ObservedEvent[];

    beforeAll(async () => {
      const session = await runner.start(scenario.id);

      try {
        await session.showInstructions();
        outcome = await session.awaitVerdict();
        events = session.events.all();
      } finally {
        // Deactivating the fault (last step of `session.stop()`) must happen
        // even if the assertions below fail, so later scenarios never observe
        // leaked fault state.
        await session.stop();
      }
    }, scenario.timeouts.vitestTestMs);

    test(
      testTitle,
      () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        const credentialEvent = events.find((event) => event.name === 'issuer.credential.requested');
        const faultAppliedEvent = events.find((event) => event.name === 'issuer.fault.applied');

        expect(
          credentialEvent,
          'Wallet must send the Credential Request through the full happy-path flow before this scenario can pass'
        ).toBeDefined();
        expect(
          faultAppliedEvent,
          'The digital-credential-claims-invalid fault must have been applied while serving the Credential Response'
        ).toBeDefined();
        expect(faultAppliedEvent?.diagnostic?.['faultProfileType']).toBe('digital-credential-claims-invalid');
        expect(faultAppliedEvent?.diagnostic?.['variant']).toBe(label);
        expect(faultAppliedEvent?.diagnostic?.['endpoint']).toBe('/credential');
        expect(
          faultAppliedEvent?.diagnostic?.['statusCode'],
          'The defective immediate response must still be served as HTTP 200'
        ).toBe(200);
        expect(faultAppliedEvent?.diagnostic?.['contentType']).toBe('application/json');

        if (label === 'type-mismatch') {
          const expectedVct = faultAppliedEvent?.diagnostic?.['expectedVct'];
          const injectedVct = faultAppliedEvent?.diagnostic?.['injectedVct'];

          expect(typeof expectedVct).toBe('string');
          expect(typeof injectedVct).toBe('string');
          expect(
            injectedVct,
            'The injected vct must differ from the nominal/requested Digital Credential type'
          ).not.toBe(expectedVct);
        } else {
          expect(
            faultAppliedEvent?.diagnostic?.['omittedClaim'],
            'The fault must report issuing_country as the only omitted required claim'
          ).toBe('issuing_country');
        }
      },
      scenario.timeouts.vitestTestMs
    );
  });

  describe('WP_061', () => {
    let outcome: ScenarioOutcome;
    let events: ObservedEvent[];

    beforeAll(async () => {
      const session = await runner.start(wp061Scenario.id);

      try {
        await session.showInstructions();
        outcome = await session.awaitVerdict();
        events = session.events.all();
      } finally {
        // Deactivating the fault (last step of `session.stop()`) must happen
        // even if the assertions below fail, so later scenarios never observe
        // leaked fault state.
        await session.stop();
      }
    }, wp061Scenario.timeouts.vitestTestMs);

    test(
      'WP_061: Wallet Instance rejects a Digital Credential whose header x5c does not chain to the Trust Anchor.',
      () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        const credentialEvent = events.find((event) => event.name === 'issuer.credential.requested');
        const faultAppliedEvent = events.find((event) => event.name === 'issuer.fault.applied');

        expect(
          credentialEvent,
          'Wallet must send the Credential Request through the full happy-path flow before this scenario can pass'
        ).toBeDefined();
        expect(
          faultAppliedEvent,
          'The edc-invalid-trust-chain fault must have been applied while serving the Credential Response'
        ).toBeDefined();
        expect(faultAppliedEvent?.diagnostic?.['faultProfileType']).toBe('edc-invalid-trust-chain');
        expect(faultAppliedEvent?.diagnostic?.['endpoint']).toBe('/credential');
        expect(
          faultAppliedEvent?.diagnostic?.['statusCode'],
          'The defective immediate response must still be served as HTTP 200'
        ).toBe(200);
        expect(faultAppliedEvent?.diagnostic?.['contentType']).toBe('application/json');

        expect(faultAppliedEvent?.diagnostic?.['mutationTarget']).toBe('x5c');
        expect(faultAppliedEvent?.diagnostic?.['strategy']).toBe('self-signed-untrusted-leaf');
        expect(
          faultAppliedEvent?.diagnostic?.['chainLength'],
          'The injected x5c must be a single self-signed leaf certificate (no intermediate)'
        ).toBe(1);
        expect(faultAppliedEvent?.diagnostic?.['certificateThumbprintSha256']).toMatch(/^[0-9a-f]{64}$/);
      },
      wp061Scenario.timeouts.vitestTestMs
    );
  });

  describe('WP_062a', () => {
    let outcome: ScenarioOutcome;
    let events: ObservedEvent[];

    beforeAll(async () => {
      const session = await runner.start(wp062aScenario.id);

      try {
        await session.showInstructions();
        outcome = await session.awaitVerdict();
        events = session.events.all();
      } finally {
        // Deactivating the fault (last step of `session.stop()`) must happen
        // even if the assertions below fail, so later scenarios never observe
        // leaked fault state.
        await session.stop();
      }
    }, wp062aScenario.timeouts.vitestTestMs);

    test(
      'WP_062a: Wallet Instance rejects a Digital Credential whose SD-JWT signature verification fails.',
      () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        const credentialEvent = events.find((event) => event.name === 'issuer.credential.requested');
        const faultAppliedEvents = events.filter((event) => event.name === 'issuer.fault.applied');
        const [faultAppliedEvent] = faultAppliedEvents;

        expect(
          credentialEvent,
          'Wallet must send the Credential Request through the full happy-path flow before this scenario can pass'
        ).toBeDefined();
        expect(
          faultAppliedEvents,
          'The edc-invalid-signature fault must have been applied exactly once while serving the Credential Response'
        ).toHaveLength(1);
        expect(faultAppliedEvent?.diagnostic?.['faultProfileType']).toBe('edc-invalid-signature');
        expect(faultAppliedEvent?.diagnostic?.['endpoint']).toBe('/credential');
        expect(
          faultAppliedEvent?.diagnostic?.['statusCode'],
          'The defective immediate response must still be served as HTTP 200'
        ).toBe(200);
        expect(faultAppliedEvent?.diagnostic?.['contentType']).toBe('application/json');

        expect(faultAppliedEvent?.diagnostic?.['mutationTarget']).toBe('jws-signature');
        expect(faultAppliedEvent?.diagnostic?.['strategy']).toBe('flip-last-signature-byte-low-bit');
        expect(
          faultAppliedEvent?.diagnostic?.['signatureByteLength'],
          'The fault must report the decoded signature byte length without exposing signature material'
        ).toBeGreaterThan(0);
        expect(faultAppliedEvent?.diagnostic).not.toHaveProperty('credential');
        expect(faultAppliedEvent?.diagnostic).not.toHaveProperty('signature');
        expect(faultAppliedEvent?.diagnostic).not.toHaveProperty('disclosures');
        expect(faultAppliedEvent?.diagnostic).not.toHaveProperty('x5c');
      },
      wp062aScenario.timeouts.vitestTestMs
    );
  });

  describe('WP_062b', () => {
    let outcome: ScenarioOutcome;
    let events: ObservedEvent[];
    let credentialOfferUri: string;

    beforeAll(async () => {
      const session = await runner.start(wp062bScenario.id);

      try {
        await session.showInstructions();
        outcome = await session.awaitVerdict();
        events = session.events.all();
        credentialOfferUri = session.stimulus.type === 'credential-offer' ? session.stimulus.uri : '';
      } finally {
        // Deactivating the fault (last step of `session.stop()`) must happen
        // even if the assertions below fail, so later scenarios never observe
        // leaked fault state.
        await session.stop();
      }
    }, wp062bScenario.timeouts.vitestTestMs);

    test(
      'WP_062b: Wallet Instance rejects an mDL mdoc-CBOR credential whose MSO COSE signature verification fails.',
      () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        const credentialOfferGeneratedEvent = events.find((event) => event.name === 'credential_offer.generated');
        const credentialEvent = events.find((event) => event.name === 'issuer.credential.requested');
        const faultAppliedEvents = events.filter((event) => event.name === 'issuer.fault.applied');
        const [faultAppliedEvent] = faultAppliedEvents;

        expect(
          credentialOfferGeneratedEvent,
          'The runner must record safe evidence for the mDL Credential Offer shown to the wallet'
        ).toBeDefined();
        expect(credentialOfferGeneratedEvent?.diagnostic?.['credentialConfigurationId']).toBe('org.iso.18013.5.1.mDL');

        const offerPayload = decodeCredentialOfferUri(credentialOfferUri);
        expect(
          offerPayload.credential_configuration_ids,
          'The shown Credential Offer must contain exactly the mDL configuration id'
        ).toEqual(['org.iso.18013.5.1.mDL']);

        expect(
          credentialEvent,
          'Wallet must send the mDL Credential Request through the full happy-path flow before this scenario can pass'
        ).toBeDefined();
        const credentialRequestParseResult = zCredentialRequestV1_3.safeParse(credentialEvent?.diagnostic?.['body']);
        expect(
          credentialRequestParseResult.success,
          'issuer.credential.requested evidence body must be a valid IT-Wallet v1.3/v1.4 Credential Request'
        ).toBe(true);
        if (!credentialRequestParseResult.success) {
          throw new Error(credentialRequestParseResult.error.message);
        }
        expect(credentialRequestParseResult.data.credential_identifier).toBe('org.iso.18013.5.1.mDL');

        expect(
          faultAppliedEvents,
          'The mdl-invalid-signature fault must have been applied exactly once while serving the Credential Response'
        ).toHaveLength(1);
        expect(faultAppliedEvent?.diagnostic?.['faultProfileType']).toBe('mdl-invalid-signature');
        expect(faultAppliedEvent?.diagnostic?.['endpoint']).toBe('/credential');
        expect(faultAppliedEvent?.diagnostic?.['resolvedSpecVersion']).toBe('1.4');
        expect(
          faultAppliedEvent?.diagnostic?.['statusCode'],
          'The defective immediate response must still be served as HTTP 200'
        ).toBe(200);
        expect(faultAppliedEvent?.diagnostic?.['contentType']).toBe('application/json');
        expect(faultAppliedEvent?.diagnostic?.['credentialConfigurationId']).toBe('org.iso.18013.5.1.mDL');
        expect(faultAppliedEvent?.diagnostic?.['mutationTarget']).toBe('issuerAuth.cose-signature');
        expect(faultAppliedEvent?.diagnostic?.['strategy']).toBe('flip-last-signature-byte-low-bit');
        expect(
          faultAppliedEvent?.diagnostic?.['signatureByteLength'],
          'The fault must report the decoded COSE signature byte length without exposing signature material'
        ).toBeGreaterThan(0);

        // The matrix cannot inspect wallet secure storage. Cryptographic
        // single-defect isolation is covered by the focused issuer unit tests;
        // this assertion block proves protocol delivery of the controlled
        // mdoc-CBOR fault and leaves UI/storage rejection to the operator.
        expect(faultAppliedEvent?.diagnostic).not.toHaveProperty('credential');
        expect(faultAppliedEvent?.diagnostic).not.toHaveProperty('issuerAuth');
        expect(faultAppliedEvent?.diagnostic).not.toHaveProperty('signature');
        expect(faultAppliedEvent?.diagnostic).not.toHaveProperty('x5chain');
      },
      wp062bScenario.timeouts.vitestTestMs
    );
  });

  describe('WP_065 / WP_066 deferred batch issuance', () => {
    let outcome: ScenarioOutcome;
    let events: ObservedEvent[];
    let batchSize: number;
    let allowedProofSigningAlgorithms: string[];
    let offeredCredentialIdentifiers: string[];
    let requestedCredentialIdentifier: string;
    let nonceEvent: ObservedEvent;
    let credentialEvent: ObservedEvent;
    let credentialRequestUrl: string;
    let credentialRequest: CredentialRequestV1_3;
    let cNonceSha256: string;
    let credentialDpopJwt: string;
    let credentialDpopHeader: DpopJwtHeader;
    let credentialDpopPayload: DpopJwtPayload;
    let credentialProofJwts: string[];
    let credentialProofHeaders: ProofJwtHeaderV1_3[];
    let credentialProofPayloads: ProofJwtPayload[];

    beforeAll(async () => {
      const session = await runner.start(wpDeferredScenario.id);
      const credentialOfferUri = session.stimulus.type === 'credential-offer' ? session.stimulus.uri : '';

      try {
        await session.showInstructions();
        outcome = await session.awaitVerdict();
        events = session.events.all();

        const offerPayload = decodeCredentialOfferUri(credentialOfferUri);
        if (
          !Array.isArray(offerPayload.credential_configuration_ids) ||
          offerPayload.credential_configuration_ids.length !== 2
        ) {
          throw new Error(
            'WP_Deferred Credential Offer must contain exactly 2 credential_configuration_ids to enable batch issuance'
          );
        }
        offeredCredentialIdentifiers = offerPayload.credential_configuration_ids;

        const credentialOfferEvent = events.find((event) => event.name === 'credential_offer.generated');
        const credentialConfigurationIds = credentialOfferEvent?.diagnostic?.['credentialConfigurationIds'];
        if (
          !Array.isArray(credentialConfigurationIds) ||
          !credentialConfigurationIds.every(
            (credentialConfigurationId) => typeof credentialConfigurationId === 'string'
          )
        ) {
          throw new Error(
            'credential_offer.generated evidence is missing the credentialConfigurationIds required to assert WP_058'
          );
        }
        expect(credentialConfigurationIds).toEqual(offeredCredentialIdentifiers);

        const discoveryUrl = new URL('/.well-known/openid-federation', config['credential-issuer'].url);
        const response = await httpsRequest({
          method: 'GET',
          hostname: discoveryUrl.hostname,
          path: discoveryUrl.pathname,
          port: discoveryUrl.port,
          protocol: discoveryUrl.protocol,
          rejectUnauthorized: false,
          signal: AbortSignal.timeout(10_000)
        });

        if (response.statusCode !== 200) {
          throw new Error(
            `Unable to fetch Credential Issuer entity configuration while WP_Deferred is active (${response.statusCode ?? 'unknown'}): ${response.body}`
          );
        }

        const issuerMetadata = decodeEntityConfiguration(response.body).metadata?.openid_credential_issuer;
        const publishedBatchSize = issuerMetadata?.batch_credential_issuance?.batch_size;
        if (
          typeof publishedBatchSize !== 'number' ||
          !Number.isInteger(publishedBatchSize) ||
          publishedBatchSize <= 0
        ) {
          throw new Error(
            'Credential Issuer metadata must publish openid_credential_issuer.batch_credential_issuance.batch_size as a positive integer for WP_058'
          );
        }
        if (publishedBatchSize < 2) {
          throw new Error(
            `Credential Issuer metadata batch_size must be at least 2 for batch issuance assertions, found ${publishedBatchSize}`
          );
        }
        batchSize = publishedBatchSize;

        const foundNonceEvent = events.find((event) => event.name === 'issuer.nonce.requested');
        if (!foundNonceEvent) {
          throw new Error('Missing issuer.nonce.requested evidence required to assert WP_058b requirements');
        }
        nonceEvent = foundNonceEvent;
        cNonceSha256 = requiredDiagnosticString(nonceEvent, 'cNonceSha256');

        const foundCredentialEvent = events.find((event) => event.name === 'issuer.credential.requested');
        if (!foundCredentialEvent) {
          throw new Error('Missing issuer.credential.requested evidence required to assert WP_058 requirements');
        }
        credentialEvent = foundCredentialEvent;

        const credentialEndpoint = requiredDiagnosticString(credentialEvent, 'endpoint');
        credentialRequestUrl = `${config['credential-issuer'].url}${credentialEndpoint}`;

        const credentialRequestParseResult = zCredentialRequestV1_3.safeParse(credentialEvent.diagnostic?.['body']);
        if (!credentialRequestParseResult.success) {
          throw new Error(
            `issuer.credential.requested evidence body is not a valid IT-Wallet v1.3/v1.4 Credential Request: ${credentialRequestParseResult.error.message}`
          );
        }
        credentialRequest = credentialRequestParseResult.data;
        if (!credentialRequest.credential_identifier) {
          throw new Error('Batch Credential Request is missing credential_identifier');
        }
        requestedCredentialIdentifier = credentialRequest.credential_identifier;
        if (!offeredCredentialIdentifiers.includes(requestedCredentialIdentifier)) {
          throw new Error(
            `Batch Credential Request used ${requestedCredentialIdentifier}, which is not one of the shown Credential Offer identifiers: ${offeredCredentialIdentifiers.join(', ')}`
          );
        }
        credentialProofJwts = credentialRequest.proofs.jwt;

        const credentialConfiguration =
          issuerMetadata?.credential_configurations_supported[requestedCredentialIdentifier];
        if (!credentialConfiguration) {
          throw new Error(
            `Credential Issuer metadata is missing credential_configurations_supported.${requestedCredentialIdentifier} for WP_058a`
          );
        }
        allowedProofSigningAlgorithms = [
          ...credentialConfiguration.proof_types_supported.jwt.proof_signing_alg_values_supported
        ];

        credentialDpopJwt = requiredDiagnosticString(credentialEvent, 'dpopProof');
        ({ header: credentialDpopHeader, payload: credentialDpopPayload } = decodeJwt({
          jwt: credentialDpopJwt,
          headerSchema: zDpopJwtHeader,
          payloadSchema: zDpopJwtPayload
        }));

        const proofArtifacts = credentialProofJwts.map((jwt) =>
          decodeJwt({
            jwt,
            headerSchema: zProofJwtHeaderV1_3,
            payloadSchema: zProofJwtPayload
          })
        );
        credentialProofHeaders = proofArtifacts.map(({ header }) => header);
        credentialProofPayloads = proofArtifacts.map(({ payload }) => payload);
      } finally {
        await session.stop();
      }
    }, wpDeferredScenario.timeouts.vitestTestMs);

    test(
      'WP_058: Wallet Instance sends a complete Batch Credential Request bound to DPoP access-token authentication and one of the offered credential identifiers.',
      async () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        expect(credentialEvent.diagnostic?.['endpoint'], 'Batch Credential Request should call /credential').toBe(
          '/credential'
        );
        expect(credentialEvent.diagnostic?.['method'], 'Batch Credential Request should use POST').toBe('POST');

        const contentType = requiredDiagnosticString(credentialEvent, 'contentType');
        expect(contentType.toLowerCase(), 'Batch Credential Request should use JSON content').toContain(
          'application/json'
        );

        expect(
          credentialEvent.diagnostic?.['authorizationScheme'],
          'Batch Credential Request should use DPoP authorization'
        ).toBe('DPoP');
        expect(
          requiredDiagnosticString(credentialEvent, 'accessTokenSha256'),
          'Batch Credential Request evidence should include the access token hash'
        ).not.toHaveLength(0);
        expect(credentialDpopJwt, 'Batch Credential Request should include a DPoP proof JWT').not.toHaveLength(0);

        expect(credentialDpopHeader.typ, 'Credential DPoP JWT typ should be dpop+jwt').toBe('dpop+jwt');
        expect(credentialDpopHeader.alg, 'Credential DPoP JWT alg should not be none').not.toBe('none');
        expect(credentialDpopHeader.jwk, 'Credential DPoP JWT header should include a public JWK').toBeDefined();
        expect(credentialDpopHeader.jwk.kty, 'Credential DPoP key should not be symmetric').not.toBe('oct');
        expect(
          credentialDpopHeader.jwk.d,
          'Credential DPoP JWT header should not expose private key material'
        ).toBeUndefined();

        const publicKey = await importJWK(credentialDpopHeader.jwk as JWK, credentialDpopHeader.alg);
        await expect(
          jwtVerify(credentialDpopJwt, publicKey),
          'Credential DPoP proof signature should verify with the declared public JWK'
        ).resolves.toBeDefined();

        expect(credentialDpopPayload.htm, 'Credential DPoP proof should be bound to POST').toBe('POST');
        expect(credentialDpopPayload.htu, 'Credential DPoP proof should be bound to the Credential Endpoint URL').toBe(
          htuFromRequestUrl(credentialRequestUrl)
        );
        expect(credentialDpopPayload.iat, 'Credential DPoP proof should carry a numeric iat').toBeTypeOf('number');
        const iatMs = credentialDpopPayload.iat * 1000;
        const eventMs = new Date(credentialEvent.timestamp).getTime();
        expect(
          Math.abs(eventMs - iatMs),
          'Credential DPoP proof iat should be fresh relative to the Credential Request event'
        ).toBeLessThanOrEqual(DPOP_IAT_FRESHNESS_TOLERANCE_SECONDS * 1000);
        expect(credentialDpopPayload.jti, 'Credential DPoP proof should carry a non-empty jti').not.toHaveLength(0);
        expect(credentialDpopPayload.ath, 'Credential DPoP ath should match the access token hash').toBe(
          requiredDiagnosticString(credentialEvent, 'accessTokenSha256')
        );

        expect(
          credentialRequest.credential_identifier,
          'Batch Credential Request should request the credential identifier from the shown offer'
        ).toBeOneOf([...offeredCredentialIdentifiers]);
        expect(credentialProofJwts, 'Batch Credential Request should include proofs.jwt entries').toHaveLength(
          batchSize
        );
      },
      wpDeferredScenario.timeouts.vitestTestMs
    );

    test(
      'WP_058a: Wallet Instance sends N fresh holder-binding proof keys that are public, asymmetric, distinct within the batch, and separate from the DPoP key.',
      async () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        expect(
          credentialProofHeaders,
          `Expected ${batchSize} decoded holder-binding proof JWT headers from the batch request`
        ).toHaveLength(batchSize);

        const credentialProofThumbprints: string[] = [];
        for (const [index, proofHeader] of credentialProofHeaders.entries()) {
          expect(proofHeader.typ, `Credential proof ${index} typ should identify an OID4VCI proof JWT`).toBe(
            'openid4vci-proof+jwt'
          );
          expect(proofHeader.alg, `Credential proof ${index} alg should not be none`).not.toBe('none');
          expect(
            proofHeader.alg,
            `Credential proof ${index} alg should be published for ${requestedCredentialIdentifier}`
          ).toBeOneOf([...allowedProofSigningAlgorithms]);
          expect(proofHeader.jwk, `Credential proof ${index} should include a public JWK`).toBeDefined();
          expect(proofHeader.jwk.kty, `Credential proof ${index} JWK should not be symmetric`).not.toBe('oct');
          expect(
            proofHeader.jwk.k,
            `Credential proof ${index} JWK should not expose symmetric key material`
          ).toBeUndefined();
          expect(
            proofHeader.jwk.d,
            `Credential proof ${index} JWK should not expose private key material`
          ).toBeUndefined();

          const publicKey = await importJWK(proofHeader.jwk as JWK, proofHeader.alg);
          await expect(
            jwtVerify(credentialProofJwts[index], publicKey),
            `Credential proof ${index} signature should verify with the declared public JWK`
          ).resolves.toBeDefined();

          credentialProofThumbprints.push(await calculateJwkThumbprint(proofHeader.jwk as JWK));
        }

        expect(
          credentialProofThumbprints,
          `Expected ${batchSize} holder-binding JWK thumbprints from the batch request`
        ).toHaveLength(batchSize);
        expect(
          new Set(credentialProofThumbprints).size,
          'WP_058a can prove uniqueness within this observed batch request; prior wallet sessions are outside protocol-observed evidence'
        ).toBe(batchSize);

        const credentialDpopThumbprint = await calculateJwkThumbprint(credentialDpopHeader.jwk as JWK);
        expect(
          credentialProofThumbprints.includes(credentialDpopThumbprint),
          'No holder-binding proof JWK should reuse the Credential Request DPoP key'
        ).toBe(false);
      },
      wpDeferredScenario.timeouts.vitestTestMs
    );

    test(
      'WP_058b: Wallet Instance signs all N holder-binding proof JWTs with the c_nonce obtained from the Nonce Endpoint and fresh iat claims.',
      () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        expect(nonceEvent.diagnostic?.['endpoint'], 'should call the Nonce Endpoint').toBe('/nonce');
        expect(nonceEvent.diagnostic?.['method'], 'Nonce Request should use POST').toBe('POST');
        expect(nonceEvent.monotonicMs, 'Nonce Request should happen before the Credential Request').toBeLessThan(
          credentialEvent.monotonicMs
        );
        expect(cNonceSha256, 'Nonce evidence should include a non-empty c_nonce hash').not.toHaveLength(0);
        expect(
          credentialProofPayloads,
          `Expected ${batchSize} decoded holder-binding proof JWT payloads from the batch request`
        ).toHaveLength(batchSize);

        const proofNonceHashes = credentialProofPayloads.map((proofPayload, index) => {
          expect(proofPayload.nonce, `Credential proof ${index} should carry a non-empty nonce`).not.toHaveLength(0);
          expect(proofPayload.iat, `Credential proof ${index} should carry a numeric iat`).toBeTypeOf('number');

          const proofIatMs = proofPayload.iat * 1000;
          const credentialRequestMs = new Date(credentialEvent.timestamp).getTime();
          expect(
            Math.abs(credentialRequestMs - proofIatMs),
            `Credential proof ${index} iat should be fresh relative to the Credential Request event`
          ).toBeLessThanOrEqual(DPOP_IAT_FRESHNESS_TOLERANCE_SECONDS * 1000);

          return sha256Base64Url(proofPayload.nonce);
        });

        expect(
          new Set(proofNonceHashes).size,
          'All holder-binding proof JWTs should reuse the same Nonce Endpoint c_nonce'
        ).toBe(1);
        for (const [index, proofNonceHash] of proofNonceHashes.entries()) {
          expect(proofNonceHash, `Credential proof ${index} nonce hash should match issuer.nonce.requested`).toBe(
            cNonceSha256
          );
        }
      },
      wpDeferredScenario.timeouts.vitestTestMs
    );

    test(
      'WP_065: Wallet Instance recognizes a Credential Response containing transaction_id and interval as deferred issuance.',
      () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        const proofCount = credentialProofJwts.length;
        expect(proofCount, `The wallet must request exactly the published batch_size of ${batchSize}`).toBe(batchSize);

        const deferredEvents = events.filter((event) => event.name === 'issuer.credential.deferred');
        expect(deferredEvents, 'Exactly one initial deferred Credential Response must be observed').toHaveLength(1);
        const [deferredEvent] = deferredEvents;
        if (!deferredEvent) {
          throw new Error('Missing issuer.credential.deferred evidence');
        }

        expect(deferredEvent.diagnostic?.['endpoint']).toBe('/credential');
        expect(deferredEvent.diagnostic?.['statusCode']).toBe(202);
        expect(deferredEvent.diagnostic?.['contentType']).toBe('application/json');
        expect(deferredEvent.diagnostic?.['responseKind']).toBe('deferred');
        expect(deferredEvent.diagnostic?.['credentialsPresent']).toBe(false);
        expect(deferredEvent.diagnostic?.['proofCount']).toBe(proofCount);
        expect(deferredEvent.diagnostic?.['credentialCount']).toBe(proofCount);

        const intervalSeconds = requiredDiagnosticNumber(deferredEvent, 'intervalSeconds');
        expect(Number.isInteger(intervalSeconds), 'interval must be an integer number of seconds').toBe(true);
        expect(intervalSeconds, 'interval must be positive').toBeGreaterThan(0);
        expect(
          requiredDiagnosticString(deferredEvent, 'transactionIdSha256'),
          'Deferred response evidence must include a non-empty transaction_id hash'
        ).not.toHaveLength(0);

        const initialCredentialResponse = findHttpResponseSentEvent(events, deferredEvent.requestId);
        expect(
          initialCredentialResponse,
          'The deferred semantic event must pair to the actual HTTP response'
        ).toBeDefined();
        expect(initialCredentialResponse?.http.statusCode).toBe(202);
        expect(initialCredentialResponse?.http.contentType.toLowerCase()).toContain('application/json');

        const credentialResponse = findHttpResponseSentEvent(events, credentialEvent.requestId);
        expect(
          credentialResponse?.http.statusCode,
          'The /credential response for this scenario must not be an immediate HTTP 200 credential payload'
        ).toBe(202);
      },
      wpDeferredScenario.timeouts.vitestTestMs
    );

    test(
      'WP_066: Wallet Instance submits a Deferred Credential Request only after the required interval has passed.',
      () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        const originalProofCount = credentialProofJwts.length;

        const deferredEvent = events.find((event) => event.name === 'issuer.credential.deferred');
        expect(deferredEvent, 'The initial HTTP 202 deferred response must be observed').toBeDefined();
        if (!deferredEvent) {
          throw new Error('Missing issuer.credential.deferred evidence');
        }

        const transactionIdSha256 = requiredDiagnosticString(deferredEvent, 'transactionIdSha256');
        const intervalSeconds = requiredDiagnosticNumber(deferredEvent, 'intervalSeconds');

        const initialCredentialResponse = findHttpResponseSentEvent(events, deferredEvent.requestId);
        expect(
          initialCredentialResponse,
          'The initial deferred event must pair to HTTP response-send evidence'
        ).toBeDefined();
        if (!initialCredentialResponse) {
          throw new Error('Missing HTTP response evidence for the initial deferred response');
        }

        const issuedEvents = events.filter(
          (event) =>
            event.name === 'issuer.deferred_credential.issued' &&
            event.diagnostic?.['endpoint'] === '/deferred' &&
            event.diagnostic?.['transactionIdSha256'] === transactionIdSha256
        );
        expect(issuedEvents, 'Exactly one successful deferred credential issuance must be observed').toHaveLength(1);
        const [issuedEvent] = issuedEvents;
        if (!issuedEvent) {
          throw new Error('Missing issuer.deferred_credential.issued evidence');
        }

        const timestampStr = requiredDiagnosticString(deferredEvent, 'timestamp');
        const timestampMs = new Date(timestampStr).getTime();
        const now = Date.now();

        // Controllo che now sia maggiore del timestamp dell'evento + i secondi di attesa (convertiti in ms)
        expect(
          now,
          'The current test execution time must be strictly greater than the deferred event timestamp plus the interval'
        ).toBeGreaterThan(timestampMs + intervalSeconds * 1000);

        expect(issuedEvent.diagnostic?.['credentialCount']).toBe(originalProofCount);
        expect(issuedEvent.diagnostic?.['notificationIdPresent']).toBe(true);

        const issuedResponse = findHttpResponseSentEvent(events, issuedEvent.requestId);
        expect(issuedResponse, 'The issued semantic event must pair to the actual HTTP 200 response').toBeDefined();
      },
      wpDeferredScenario.timeouts.vitestTestMs
    );

    test(
      'WP_066a: Wallet Instance sends a Deferred Credential Request as an HTTP POST with Content-Type: application/json, and the request body contains the required transaction_id',
      () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        const deferredEvent = events.find((event) => event.name === 'issuer.credential.deferred');
        expect(deferredEvent, 'The initial HTTP 202 deferred response must be observed').toBeDefined();
        if (!deferredEvent) {
          throw new Error('Missing issuer.credential.deferred evidence');
        }

        const transactionIdSha256 = requiredDiagnosticString(deferredEvent, 'transactionIdSha256');
        expect(
          transactionIdSha256,
          'Deferred response evidence must include a non-empty transaction_id hash'
        ).not.toHaveLength(0);
      },
      wpDeferredScenario.timeouts.vitestTestMs
    );
  });
});
