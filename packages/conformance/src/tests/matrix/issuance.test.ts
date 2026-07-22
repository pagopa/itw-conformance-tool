import { loadConfig, type ConfigSchemaType } from '@itw-conformance-tool/config';
import { DatabaseClient } from '@itw-conformance-tool/database';
import {
  decodeJwt,
  decodeJwtHeader,
  parseAccessTokenRequest,
  parsePushedAuthorizationRequest,
  verifyClientAttestationPopJwt,
  IT_WALLET_CLIENT_ATTESTATION_POP_ALLOWED_ALG_VALUES
} from '@pagopa/io-wallet-oauth2';
import { IoWalletSdkConfig, ItWalletSpecsVersion, type HttpMethod } from '@pagopa/io-wallet-utils';
import { importJWK, jwtVerify, type JWK } from 'jose';
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

        const tokenEvent = events.find((event) => event.name === 'issuer.token.requested');
        expect(tokenEvent).toBeDefined();

        const body = tokenEvent?.diagnostic?.['body'];
        const headers = tokenEvent?.diagnostic?.['headers'];
        const endpoint = tokenEvent?.diagnostic?.['endpoint'];

        const { pkceCodeVerifier } = parseAccessTokenRequest({
          accessTokenRequest: body as Record<string, unknown>,
          request: {
            headers: toHeaders(headers),
            method: 'POST' as HttpMethod,
            url: `${config['credential-issuer'].url}${endpoint}`
          }
        });

        expect(pkceCodeVerifier).toBeDefined();
        expect(pkceCodeVerifier).toSatisfy(isRfc7636CodeVerifier, 'code_verifier must be an RFC 7636 compliant string');
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
  });
});
