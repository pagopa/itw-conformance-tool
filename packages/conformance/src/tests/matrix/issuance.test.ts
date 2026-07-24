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
  wp054MissingCodeScenario,
  wp054aInvalidStateScenario,
  wpCiHappyScenario
} from '../../index.js';
import { httpsRequest } from '../../utils/request.js';

import type { ObservedEvent, ScenarioOutcome, ScenarioRunner } from '../../index.js';
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

function sha256Base64Url(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('base64url');
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
        `Missing ${SERVICE_CONTROL_ENDPOINT_ENV_VAR}: run this suite via the itwct CLI (e.g. itwct test issuance), which starts the local service control relay required by WP_046a and WP_054.`
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
});
