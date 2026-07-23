import { loadConfig, type ConfigSchemaType } from '@itw-conformance-tool/config';
import { DatabaseClient } from '@itw-conformance-tool/database';
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
import { IoWalletSdkConfig, ItWalletSpecsVersion, type HttpMethod } from '@pagopa/io-wallet-utils';
import { calculateJwkThumbprint, importJWK, jwtVerify, type JWK } from 'jose';
import { afterAll, beforeAll, describe, expect, test } from 'vitest';

import { isRfc7636CodeVerifier } from '../../helpers/issuance.js';
import {
  assertConformanceOutcome,
  createProtocolObservedScenarioRunner,
  createSqliteScenarioEventBridge,
  issuanceScenarioRegistry,
  wpCiHappyScenario
} from '../../index.js';

import type { ObservedEvent, ScenarioOutcome, ScenarioRunner } from '../../index.js';
import type { CallbackContext } from '@pagopa/io-wallet-oauth2';

function toHeaders(value: unknown): Headers {
  if (value === null || typeof value !== 'object') {
    throw new Error('issuer.par.requested evidence is missing header data');
  }

  const entries = Object.entries(value as Record<string, unknown>).filter(
    (entry): entry is [string, string] => typeof entry[1] === 'string'
  );

  return new Headers(entries);
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

describe('Test Cases for Issuance Phase', () => {
  let runner: ScenarioRunner;
  let db: DatabaseClient;
  let config: ConfigSchemaType;

  beforeAll(() => {
    config = loadConfig();
    db = new DatabaseClient(config.global.data_dir);

    const credentialIssuer = config['credential-issuer'].url;
    const federation = config['trust-anchor'].url;
    runner = createProtocolObservedScenarioRunner({
      endpoints: { credentialIssuer, federation },
      eventBridgeFactory: createSqliteScenarioEventBridge({ db }),
      registry: issuanceScenarioRegistry
    });
  });

  afterAll(async () => {
    await runner.close();
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
    }, wpCiHappyScenario.timeouts.vitestTestMs);

    test(
      `[WP_046]: Wallet Instance successfully uses Federation API endpoints (.well-known/openid-federation, /fetch) to retrieve current metadata and configurations of the Credential Issuer.`,
      async () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });
      },
      wpCiHappyScenario.timeouts.vitestTestMs
    );

    test(
      '[WP_051]: Wallet Instance successfully requests PID/(Q)EAA from the PID/(Q)EAA Provider using the Authorization Code Flow per OpenID4VCI.',
      () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        expect(authorizationRequest).toBeDefined();
        expect(authorizationRequest.client_id).not.toHaveLength(0);
        expect(authorizationRequest.response_type).toBe('code');
      },
      wpCiHappyScenario.timeouts.vitestTestMs
    );

    test(
      '[WP_053]: Wallet Instance sends an Authorization Request to the Credential Issuer Authorization Endpoint using the received request_uri and client_id.',
      () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        const parEvent = events.find((event) => event.name === 'issuer.par.requested');
        const authorizationEvent = events.find((event) => event.name === 'issuer.authorization.requested');

        expect(parEvent).toBeDefined();
        expect(authorizationEvent).toBeDefined();
        if (!parEvent || !authorizationEvent) {
          throw new Error('Missing issuer.par.requested or issuer.authorization.requested evidence');
        }

        expect(authorizationEvent.diagnostic?.['endpoint']).toBe('/authorize');

        const parRequestUri = parEvent.diagnostic?.['requestUri'];
        const authorizationRequestUri = authorizationEvent.diagnostic?.['requestUri'];
        expect(typeof parRequestUri).toBe('string');
        expect(parRequestUri).not.toHaveLength(0);
        expect(authorizationRequestUri).toBe(parRequestUri);

        expect(authorizationRequest).toBeDefined();
        const authorizationClientId = authorizationEvent.diagnostic?.['clientId'];
        expect(typeof authorizationClientId).toBe('string');
        expect(authorizationClientId).not.toHaveLength(0);
        expect(authorizationClientId).toBe(authorizationRequest.client_id);
      },
      wpCiHappyScenario.timeouts.vitestTestMs
    );

    test(
      '[WP_052a]: Wallet Instance creates the code_verifier following RFC 7636 recommendations for random number generation to prevent brute-force attacks.',
      () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        expect(tokenRequestResult.pkceCodeVerifier).toBeDefined();
        expect(tokenRequestResult.pkceCodeVerifier).toSatisfy(
          isRfc7636CodeVerifier,
          'code_verifier must be an RFC 7636 compliant string'
        );
      },
      wpCiHappyScenario.timeouts.vitestTestMs
    );

    test(
      "[WP_052b]: Wallet Instance generates the Wallet Attestation PoP JWT and binds it to the same ephemeral public key referenced in the Wallet Attestation's cnf.jwk.",
      async () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });
        expect(clientAttestation).toBeDefined();
        if (!clientAttestation) {
          throw new Error('PAR request is missing client attestation headers');
        }

        // The Wallet Attestation payload's `cnf.jwk` is mandatory per the SDK's
        // `zWalletAttestationJwtPayloadV1_0`/`V1_3`/`V1_4` schemas.
        const { payload: attestationPayload } = decodeJwt({ jwt: clientAttestation.walletAttestationJwt });
        const cnfJwk = attestationPayload.cnf?.jwk;
        expect(cnfJwk).toBeDefined();
        if (!cnfJwk) {
          throw new Error('Wallet Attestation payload is missing cnf.jwk');
        }

        const { header: popHeader } = decodeJwtHeader({ jwt: clientAttestation.clientAttestationPopJwt });
        expect(popHeader.typ).toBe('oauth-client-attestation-pop+jwt');
        expect(popHeader.alg).toBeOneOf([...IT_WALLET_CLIENT_ATTESTATION_POP_ALLOWED_ALG_VALUES]);

        // Binding assertion: per the IT-Wallet profile, the PoP JWT header does
        // not itself carry a key reference (no `jwk`/`kid` — both are optional
        // per the SDK's `zItWalletClientAttestationPopJwtHeader` and are absent
        // in practice); the verifier is expected to already know the key from
        // the associated Wallet Attestation's `cnf.jwk`. The only way to prove
        // the PoP JWT is bound to that same ephemeral key is to verify its
        // signature directly against it.
        const publicKey = await importJWK(cnfJwk as JWK, popHeader.alg);
        await expect(jwtVerify(clientAttestation.clientAttestationPopJwt, publicKey)).resolves.toBeDefined();
      },
      wpCiHappyScenario.timeouts.vitestTestMs
    );

    test(
      "[WP_052c]: Wallet Instance signs the PoP JWT with the ephemeral private key corresponding to the public key in the Wallet Attestation's cnf.jwk.",
      async () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });
        expect(clientAttestation).toBeDefined();
        if (!clientAttestation) {
          throw new Error('PAR request is missing client attestation headers');
        }

        const { payload: attestationPayload } = decodeJwt({ jwt: clientAttestation.walletAttestationJwt });
        const cnfJwk = attestationPayload.cnf?.jwk;
        expect(cnfJwk).toBeDefined();
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
          })
        ).resolves.toBeDefined();
      },
      wpCiHappyScenario.timeouts.vitestTestMs
    );

    test(
      '[WP_052d]: Wallet Instance embeds correct Digital Credential types in the Request Object using the authorization_details (or scope) parameter.',
      () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });
        expect(authorizationRequest).toBeDefined();

        // Matches the credential_configuration_ids requested in createCredentialOfferUri().
        const expectedCredentialConfigurationId = 'dc_sd_jwt_EuropeanDisabilityCard';

        const hasMatchingAuthorizationDetail = authorizationRequest.authorization_details?.some(
          (detail) =>
            detail.type === 'openid_credential' &&
            detail.credential_configuration_id === expectedCredentialConfigurationId
        );
        const hasMatchingScope = authorizationRequest.scope?.split(/\s+/).includes(expectedCredentialConfigurationId);

        expect(hasMatchingAuthorizationDetail || hasMatchingScope).toBe(true);
      },
      wpCiHappyScenario.timeouts.vitestTestMs
    );

    test(
      '[WP_055]: Wallet Instance sends the Token Request to the Credential Issuer Token Endpoint using the authorization_code grant with the code, redirect_uri and PKCE code_verifier.',
      () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        expect(tokenEvent.diagnostic?.['endpoint']).toBe('/token');

        const tokenRequestHeaders = toHeaders(tokenEvent.diagnostic?.['headers']);
        const contentType = tokenRequestHeaders.get('content-type');
        expect(contentType).not.toBeNull();
        expect(contentType?.toLowerCase()).toContain('application/x-www-form-urlencoded');

        expect(tokenRequestResult.grant.grantType).toBe('authorization_code');
        if (tokenRequestResult.grant.grantType !== 'authorization_code') {
          throw new Error('Expected the Token Request to use the authorization_code grant');
        }
        expect(tokenRequestResult.grant.code).not.toHaveLength(0);

        const { accessTokenRequest } = tokenRequestResult;
        expect(accessTokenRequest.grant_type).toBe('authorization_code');
        if (accessTokenRequest.grant_type !== 'authorization_code') {
          throw new Error('Expected the Token Request body to use the authorization_code grant');
        }

        // The redirect_uri from the Token Request must match the one carried
        // in the PAR Request Object, proving the Wallet Instance presents the
        // same redirection endpoint it registered during authorization.
        expect(authorizationRequest).toBeDefined();
        expect(accessTokenRequest.redirect_uri).toBe(authorizationRequest.redirect_uri);

        expect(tokenRequestResult.pkceCodeVerifier).toBeDefined();
        expect(tokenRequestResult.pkceCodeVerifier).not.toHaveLength(0);
      },
      wpCiHappyScenario.timeouts.vitestTestMs
    );

    test(
      '[WP_055a]: Wallet Instance authenticates the Token Request with the DPoP proof, the Wallet Attestation and the Wallet Instance PoP, sent as three distinct JWT headers.',
      () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        expect(tokenRequestResult.dpop.jwt).not.toHaveLength(0);
        expect(tokenRequestResult.clientAttestation.walletAttestationJwt).not.toHaveLength(0);
        expect(tokenRequestResult.clientAttestation.clientAttestationPopJwt).not.toHaveLength(0);

        const { header: dpopHeader } = decodeJwtHeader({
          jwt: tokenRequestResult.dpop.jwt,
          headerSchema: zDpopJwtHeader
        });
        expect(dpopHeader.typ).toBe('dpop+jwt');

        // Confirms the Wallet Attestation header decodes as a well-formed JWT;
        // its `typ` is version-dependent (see zWalletAttestationJwtHeaderV1_0/
        // V1_3/V1_4 in the SDK) and is intentionally not pinned to one value here.
        expect(() => decodeJwtHeader({ jwt: tokenRequestResult.clientAttestation.walletAttestationJwt })).not.toThrow();

        const { header: popHeader } = decodeJwtHeader({
          jwt: tokenRequestResult.clientAttestation.clientAttestationPopJwt,
          headerSchema: zItWalletClientAttestationPopJwtHeader
        });
        expect(popHeader.typ).toBe('oauth-client-attestation-pop+jwt');
      },
      wpCiHappyScenario.timeouts.vitestTestMs
    );

    test(
      '[WP_055b]: Wallet Instance generates a fresh DPoP key for the Token Request, with a proof JWT conforming to RFC 9449 and bound to the Token Endpoint.',
      () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        const { header: dpopHeader, payload: dpopPayload } = decodeJwt({
          jwt: tokenRequestResult.dpop.jwt,
          headerSchema: zDpopJwtHeader,
          payloadSchema: zDpopJwtPayload
        });

        expect(dpopHeader.typ).toBe('dpop+jwt');
        expect(dpopHeader.alg).not.toBe('none');

        expect(dpopHeader.jwk).toBeDefined();
        expect(dpopHeader.jwk.d).toBeUndefined();

        expect(dpopPayload.htm).toBe('POST');
        expect(dpopPayload.htu).toBe(htuFromRequestUrl(tokenRequestUrl));

        expect(dpopPayload.iat).toBeTypeOf('number');
        const iatMs = dpopPayload.iat * 1000;
        const eventMs = new Date(tokenEvent.timestamp).getTime();
        expect(Math.abs(eventMs - iatMs)).toBeLessThanOrEqual(DPOP_IAT_FRESHNESS_TOLERANCE_SECONDS * 1000);

        expect(dpopPayload.jti).not.toHaveLength(0);

        // Reuse of the PAR DPoP proof/key for the Token Request would defeat
        // the purpose of per-request proof-of-possession, so both the `jti`
        // and the JWK thumbprint (RFC 7638) must differ from the PAR DPoP.
        expect(clientAttestation).toBeDefined();
        if (!clientAttestation) {
          throw new Error('Missing DPoP proof from the PAR request needed to assert key rotation');
        }
        const { payload: parDpopPayload } = decodeJwt({
          jwt: clientAttestation?.clientAttestationPopJwt,
          headerSchema: zItWalletClientAttestationPopJwtHeader,
          payloadSchema: zItWalletClientAttestationPopJwtPayload
        });
        expect(dpopPayload.jti).not.toBe(parDpopPayload.jti);

        expect(jwtVerify(clientAttestation?.clientAttestationPopJwt, dpopHeader.jwk)).rejects.toThrow();
      },
      wpCiHappyScenario.timeouts.vitestTestMs
    );

    test(
      '[WP_055c]: Wallet Instance signs the Token Request DPoP proof with the private key matching the public JWK declared in the DPoP proof header.',
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
        await expect(jwtVerify(tokenRequestResult.dpop.jwt, publicKey)).resolves.toBeDefined();
      },
      wpCiHappyScenario.timeouts.vitestTestMs
    );

    test(
      '[WP_055d]: Wallet Instance binds the Token Request to the Wallet Instance ephemeral key by signing the Wallet Instance PoP with the private key matching the Wallet Attestation cnf.jwk.',
      async () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        const { payload: attestationPayload } = decodeJwt({
          jwt: tokenRequestResult.clientAttestation.walletAttestationJwt
        });
        const cnfJwk = attestationPayload.cnf?.jwk;
        expect(cnfJwk).toBeDefined();
        if (!cnfJwk) {
          throw new Error('Token Request Wallet Attestation payload is missing cnf.jwk');
        }

        const { header: popHeader, payload: popPayload } = decodeJwt({
          jwt: tokenRequestResult.clientAttestation.clientAttestationPopJwt,
          headerSchema: zItWalletClientAttestationPopJwtHeader,
          payloadSchema: zItWalletClientAttestationPopJwtPayload
        });
        expect(popHeader.typ).toBe('oauth-client-attestation-pop+jwt');
        expect(popHeader.alg).toBeOneOf([...IT_WALLET_CLIENT_ATTESTATION_POP_ALLOWED_ALG_VALUES]);

        expect(popPayload.aud).toBe(config['credential-issuer'].url);
        expect(popPayload.iat).toBeTypeOf('number');
        expect(popPayload.iss).not.toHaveLength(0);
        expect(popPayload.jti).not.toHaveLength(0);

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
          })
        ).resolves.toBeDefined();
      },
      wpCiHappyScenario.timeouts.vitestTestMs
    );
  });
});
