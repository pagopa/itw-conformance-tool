import { createHash, randomUUID } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import { inflateSync } from 'node:zlib';

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
  zWalletAttestationJwtHeaderV1_4,
  zWalletAttestationJwtPayloadV1_4,
  IT_WALLET_CLIENT_ATTESTATION_POP_ALLOWED_ALG_VALUES
} from '@pagopa/io-wallet-oauth2';
import { zCredentialRequestV1_3, zProofJwtHeaderV1_3, zProofJwtPayload } from '@pagopa/io-wallet-oid4vci';
import { IoWalletSdkConfig, ItWalletSpecsVersion, type HttpMethod } from '@pagopa/io-wallet-utils';
import { calculateJwkThumbprint, importJWK, importX509, jwtVerify, type JWK } from 'jose';
import { afterAll, beforeAll, describe, expect, test } from 'vitest';

import { trimTrailingSlash } from '../../helpers/general.js';
import { isRfc7636CodeVerifier } from '../../helpers/issuance.js';
import { decodeEntityConfiguration } from '../../helpers/provider.js';
import {
  assertConformanceOutcome,
  createProtocolObservedScenarioRunner,
  createSqliteScenarioEventBridge,
  issuanceScenarioRegistry,
  wp017Scenario,
  WP_050A_METADATA_POLICY_CREDENTIAL_CONFIGURATION_ID,
  wp050aMetadataPolicyScenario,
  wp046aScenario,
  WP_UNSUPPORTED_CREDENTIAL_CONFIGURATION_ID,
  wpUnsupportedCredentialOfferScenario,
  wp057Scenario,
  wp059Scenario,
  wp060TypeMismatchScenario,
  wp061Scenario,
  wp062aScenario,
  wp062bScenario,
  wpNotificationScenario,
  wpDeferredScenario,
  WP_CREDENTIAL_REISSUANCE_INITIAL_REFRESH_TOKEN_TTL_SECONDS,
  WP_CREDENTIAL_REISSUANCE_INITIAL_TOKEN_TTL_SECONDS,
  WP_CREDENTIAL_REISSUANCE_REFRESHED_ACCESS_TOKEN_TTL_SECONDS,
  WP_CREDENTIAL_REISSUANCE_STATUS_INDEX,
  WP_CREDENTIAL_REISSUANCE_UPDATED_STATUS,
  WP_CREDENTIAL_REISSUANCE_VALID_ACCESS_TOKEN_TTL_SECONDS,
  wp054MissingCodeScenario,
  wp054aInvalidStateScenario,
  wp054bInvalidIssuerScenario,
  wpCiHappyScenario,
  wpCredentialReissuanceRefreshAccessTokenScenario,
  wpCredentialReissuanceRefreshAccessTokenUpdatedIssuerConfig,
  wpCredentialReissuanceScenario,
  wpCredentialReissuanceUpdatedIssuerConfig,
  wpCredentialReissuanceValidAccessTokenScenario,
  wpCredentialReissuanceValidAccessTokenUpdatedIssuerConfig
} from '../../index.js';
import { httpsRequest } from '../../utils/request.js';
import {
  certificateFromBase64Der,
  expectCertificateIssuedBy,
  expectCertificateValidAt,
  trustAnchorCertificateFromConfig
} from '../../utils/x509.js';

import type {
  HttpResponseSentEvent,
  ObservedEvent,
  ScenarioOutcome,
  ScenarioEventStore,
  ScenarioRunner
} from '../../index.js';
import type {
  CallbackContext,
  DpopJwtHeader,
  DpopJwtPayload,
  ItWalletClientAttestationPopJwtHeader,
  ItWalletClientAttestationPopJwtPayload,
  Jwk as OAuthJwk
} from '@pagopa/io-wallet-oauth2';
import type { CredentialRequestV1_3, ProofJwtHeaderV1_3, ProofJwtPayload } from '@pagopa/io-wallet-oid4vci';

function toHeaders(value: unknown, context = 'request evidence'): Headers {
  if (value === null || typeof value !== 'object') {
    throw new Error(`${context} is missing header data`);
  }

  const entries = Object.entries(value as Record<string, unknown>).filter(
    (entry): entry is [string, string] => typeof entry[1] === 'string'
  );

  return new Headers(entries);
}

function diagnosticBodyRecord(event: ObservedEvent, context: string): Record<string, unknown> {
  const body = event.diagnostic?.['body'];
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    throw new Error(`${context} evidence is missing parsed body data`);
  }

  return body as Record<string, unknown>;
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

function nthEvent(events: ObservedEvent[], name: ObservedEvent['name'], index: number): ObservedEvent {
  const event = events.filter((candidate) => candidate.name === name).at(index);
  if (!event) {
    throw new Error(`Missing ${name} event at index ${index}`);
  }

  return event;
}

function eventsByName(events: ObservedEvent[], name: ObservedEvent['name']): ObservedEvent[] {
  return events.filter((event) => event.name === name);
}

function isUpdatedStatusListEvent(event: ObservedEvent): boolean {
  return (
    event.name === 'issuer.status_list.requested' &&
    event.diagnostic?.['bits'] === 4 &&
    event.diagnostic?.['credentialIndex'] === WP_CREDENTIAL_REISSUANCE_STATUS_INDEX &&
    event.diagnostic?.['statusValue'] === WP_CREDENTIAL_REISSUANCE_UPDATED_STATUS
  );
}

async function waitForUpdatedStatusListEvent(
  sessionEvents: ScenarioEventStore,
  after: ObservedEvent,
  signal: AbortSignal | undefined,
  timeoutMs: number
): Promise<ObservedEvent> {
  let cursor = after;
  for (;;) {
    const existing = sessionEvents
      .all()
      .find((event) => isUpdatedStatusListEvent(event) && event.monotonicMs > cursor.monotonicMs);
    if (existing) return existing;

    const event = await sessionEvents.waitFor('issuer.status_list.requested', {
      after: cursor,
      timeoutMs,
      signal
    });
    if (isUpdatedStatusListEvent(event)) return event;
    cursor = event;
  }
}

function parseTokenRequestFromEvent(
  event: ObservedEvent,
  issuerBaseUrl: string
): ReturnType<typeof parseAccessTokenRequest> {
  const endpoint = requiredDiagnosticString(event, 'endpoint');
  return parseAccessTokenRequest({
    accessTokenRequest: event.diagnostic?.['body'] as Record<string, unknown>,
    request: {
      headers: toHeaders(event.diagnostic?.['headers']),
      method: 'POST' as HttpMethod,
      url: `${issuerBaseUrl}${endpoint}`
    }
  });
}

function parseCredentialRequestFromEvent(event: ObservedEvent): CredentialRequestV1_3 {
  const credentialRequestParseResult = zCredentialRequestV1_3.safeParse(event.diagnostic?.['body']);
  if (!credentialRequestParseResult.success) {
    throw new Error(
      `issuer.credential.requested evidence body is not a valid IT-Wallet v1.3/v1.4 Credential Request: ${credentialRequestParseResult.error.message}`
    );
  }

  return credentialRequestParseResult.data;
}

function getStatusFromCompressedStatusList(compressedList: string, bits: 4, index: number): number {
  const bytes = inflateSync(Buffer.from(compressedList, 'base64url'));
  const totalStatuses = (bytes.length * 8) / bits;
  const statusList = new Array<number>(totalStatuses);
  const statusesPerByte = 8 / bits;

  for (let statusIndex = 0; statusIndex < totalStatuses; statusIndex++) {
    const byte = bytes[Math.floor((statusIndex * bits) / 8)];
    if (byte === undefined) {
      throw new Error(`Status List index ${statusIndex} is out of bounds`);
    }

    const bitIndex = (statusIndex * bits) % 8;
    const byteString = byte.toString(2).padStart(8, '0');
    const group = Math.floor(statusIndex / statusesPerByte);
    const indexInGroup = statusIndex % statusesPerByte;
    const position = group * statusesPerByte + (statusesPerByte - 1 - indexInGroup);
    statusList[position] = Number.parseInt(byteString.slice(bitIndex, bitIndex + bits), 2);
  }

  const status = statusList[index];
  if (status === undefined) {
    throw new Error(`Status List index ${index} is out of bounds`);
  }

  return status;
}

async function fetchStatusListJwt(statusListUri: string): Promise<string> {
  const statusListUrl = new URL(statusListUri);
  const response = await httpsRequest<string>({
    method: 'GET',
    hostname: statusListUrl.hostname,
    path: statusListUrl.pathname,
    port: statusListUrl.port,
    protocol: statusListUrl.protocol,
    rejectUnauthorized: false,
    signal: AbortSignal.timeout(10_000)
  });

  if (response.statusCode !== 200) {
    throw new Error(`Unable to fetch Status List (${response.statusCode ?? 'unknown'}): ${response.body}`);
  }

  return response.body;
}

function decodeCredentialOfferUri(uri: string): { credential_configuration_ids?: string[] } {
  const credentialOffer = new URL(uri).searchParams.get('credential_offer');
  if (!credentialOffer) {
    throw new Error('Credential offer URI is missing the credential_offer parameter');
  }

  return JSON.parse(credentialOffer) as { credential_configuration_ids?: string[] };
}

function pemFromX5cCertificate(certificate: string): string {
  const lines = certificate.match(/.{1,64}/g);
  if (!lines) {
    throw new Error('Wallet Attestation x5c certificate is empty');
  }

  return ['-----BEGIN CERTIFICATE-----', ...lines, '-----END CERTIFICATE-----'].join('\n');
}

function requireWalletAttestationCnfJwk(
  tokenRequest: ReturnType<typeof parseAccessTokenRequest>,
  context: string
): OAuthJwk {
  const { payload } = decodeJwt({ jwt: tokenRequest.clientAttestation.walletAttestationJwt });
  const cnfJwk = payload.cnf?.jwk;
  if (!cnfJwk) {
    throw new Error(`${context} Wallet Attestation payload is missing cnf.jwk`);
  }

  return cnfJwk;
}

function expectJwtIatFresh(iat: unknown, event: ObservedEvent, context: string): void {
  expect(iat, `${context} should carry a numeric iat`).toBeTypeOf('number');
  if (typeof iat !== 'number') {
    throw new Error(`${context} iat is not numeric`);
  }

  const iatMs = iat * 1000;
  const eventMs = new Date(event.timestamp).getTime();
  expect(
    Math.abs(eventMs - iatMs),
    `${context} iat should be fresh relative to its observed event`
  ).toBeLessThanOrEqual(DPOP_IAT_FRESHNESS_TOLERANCE_SECONDS * 1000);
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
const STATUS_LIST_CACHE_CLOCK_SKEW_MS = 1_000;

const WALLET_ATTESTATION_NON_USER_PAYLOAD_CLAIMS = new Set([
  'aud',
  'cnf',
  'eudi_wallet_info',
  'exp',
  'iat',
  'iss',
  'jti',
  'nbf',
  'nonce',
  'status',
  'sub',
  'trust_chain',
  'wallet_link',
  'wallet_name'
]);

// Set by the CLI's local control relay (`itwct test issuance`/`itwct test`)
// before spawning this Vitest process; see `apps/cli/src/commands/runTests.ts`.
const SERVICE_CONTROL_ENDPOINT_ENV_VAR = 'ITWCT_SERVICE_CONTROL_ENDPOINT';

interface TokenRequestArtifact {
  event: ObservedEvent;
  dpopHeader: DpopJwtHeader;
  dpopPayload: DpopJwtPayload;
  headers: Headers;
  popHeader: ItWalletClientAttestationPopJwtHeader;
  popPayload: ItWalletClientAttestationPopJwtPayload;
  requestResult: ReturnType<typeof parseAccessTokenRequest>;
  requestUrl: string;
  walletAttestationCnfJwk: OAuthJwk;
}

function statusListExpiryMs(event: ObservedEvent): number | undefined {
  const expiresAt = event.diagnostic?.['expiresAt'];
  if (typeof expiresAt === 'string') {
    const parsed = Date.parse(expiresAt);
    if (!Number.isNaN(parsed)) return parsed;
  }

  const ttlSeconds = event.diagnostic?.['ttlSeconds'];
  if (typeof ttlSeconds === 'number') {
    return Date.parse(event.timestamp) + ttlSeconds * 1000;
  }

  return undefined;
}

function latestObservedNominalStatusListExpiryMs(events: ObservedEvent[]): number | undefined {
  const nominalStatusListEvent = events
    .filter(
      (event) =>
        event.name === 'issuer.status_list.requested' &&
        event.diagnostic?.['credentialIndex'] === WP_CREDENTIAL_REISSUANCE_STATUS_INDEX &&
        event.diagnostic?.['statusValue'] !== WP_CREDENTIAL_REISSUANCE_UPDATED_STATUS
    )
    .at(-1);

  return nominalStatusListEvent ? statusListExpiryMs(nominalStatusListEvent) : undefined;
}

async function waitUntilMs(targetMs: number, signal: AbortSignal | undefined): Promise<void> {
  const remainingMs = targetMs - Date.now();
  if (remainingMs > 0) {
    await sleep(remainingMs, undefined, { signal });
  }
}

async function waitForObservedNominalStatusListCacheExpiry(
  events: ObservedEvent[],
  signal: AbortSignal | undefined
): Promise<void> {
  const expiresAtMs = latestObservedNominalStatusListExpiryMs(events);
  if (expiresAtMs === undefined) return;

  await waitUntilMs(expiresAtMs + STATUS_LIST_CACHE_CLOCK_SKEW_MS, signal);
}

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
      issuerFaultSpecVersion: '1.4',
      trustAnchorFaultController: issuerFaultController,
      trustAnchorFaultSpecVersion: '1.4'
    });
  });

  afterAll(async () => {
    await runner?.close();
    await issuerFaultController?.close();
    db?.close();
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
      "WP_019: The Wallet Attestation contains all required claims and data points that attest to the device's integrity and security status.",
      () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });
        expect(clientAttestation, 'should parse the client attestation headers from PAR').toBeDefined();
        if (!clientAttestation) {
          throw new Error('PAR request is missing client attestation headers');
        }

        const { header: attestationHeader, payload: attestationPayload } = decodeJwt({
          jwt: clientAttestation.walletAttestationJwt,
          headerSchema: zWalletAttestationJwtHeaderV1_4,
          payloadSchema: zWalletAttestationJwtPayloadV1_4
        });

        expect(attestationHeader.alg, 'Wallet Attestation alg should not be none').not.toBe('none');
        expect(
          attestationHeader.kid,
          'Wallet Attestation should carry the Wallet Provider signing key id'
        ).not.toHaveLength(0);
        expect(attestationHeader.typ, 'Wallet Attestation typ should identify an OAuth client attestation').toBe(
          'oauth-client-attestation+jwt'
        );
        expect(attestationHeader.x5c, 'Wallet Attestation should carry an X.509 certificate chain').not.toHaveLength(0);

        expect(attestationPayload.iss, 'Wallet Attestation should carry the Wallet Provider issuer').toBe(
          trimTrailingSlash(config['wallet-provider'].url)
        );
        expect(
          attestationPayload.sub,
          'Wallet Attestation should carry a non-empty subject thumbprint'
        ).not.toHaveLength(0);
        expect(attestationPayload.iat, 'Wallet Attestation should carry a numeric iat').toBeTypeOf('number');
        expect(attestationPayload.exp, 'Wallet Attestation should carry a numeric exp').toBeTypeOf('number');
        expect(attestationPayload.exp, 'Wallet Attestation exp should be after iat').toBeGreaterThan(
          attestationPayload.iat
        );

        expect(attestationPayload.cnf.jwk, 'Wallet Attestation should carry cnf.jwk').toBeDefined();
        expect(attestationPayload.cnf.jwk.kty, 'Wallet Attestation cnf.jwk should declare a key type').not.toHaveLength(
          0
        );
        expect(
          attestationPayload.cnf.jwk.d,
          'Wallet Attestation cnf.jwk should not expose private key material'
        ).toBeUndefined();
        expect(
          attestationPayload.cnf.jwk.k,
          'Wallet Attestation cnf.jwk should not expose symmetric key material'
        ).toBeUndefined();

        expect(
          attestationPayload.wallet_link,
          'Wallet Attestation should carry the Wallet Provider information URL'
        ).toBe(trimTrailingSlash(config['wallet-provider'].url));
        expect(attestationPayload.wallet_name, 'Wallet Attestation should carry the Wallet name').toBe(
          config.wallet.wallet_name
        );
        expect(
          attestationPayload.status.status_list.uri,
          'Wallet Attestation should carry a status list URI for revocation/security status'
        ).toBeDefined();
        expect(
          attestationPayload.status.status_list.idx,
          'Wallet Attestation should carry a status list index'
        ).toBeTypeOf('number');
      },
      wpCiHappyScenario.timeouts.vitestTestMs
    );

    test(
      "WP_019b: The Wallet Attestation contains a cryptographic binding to Wallet Instance's ephemeral public key that is successfully verified.",
      async () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });
        expect(clientAttestation, 'should parse the client attestation headers from PAR').toBeDefined();
        if (!clientAttestation) {
          throw new Error('PAR request is missing client attestation headers');
        }

        const { payload: attestationPayload } = decodeJwt({
          jwt: clientAttestation.walletAttestationJwt,
          payloadSchema: zWalletAttestationJwtPayloadV1_4
        });

        const cnfJwk = attestationPayload.cnf.jwk;
        await expect(
          calculateJwkThumbprint(cnfJwk),
          'Wallet Attestation sub should be the thumbprint of cnf.jwk'
        ).resolves.toBe(attestationPayload.sub);

        const { header: popHeader } = decodeJwtHeader({ jwt: clientAttestation.clientAttestationPopJwt });
        const publicKey = await importJWK(cnfJwk as JWK, popHeader.alg);
        await expect(
          jwtVerify(clientAttestation.clientAttestationPopJwt, publicKey),
          'Wallet Instance PoP signature should verify with the Wallet Attestation cnf.jwk'
        ).resolves.toBeDefined();
      },
      wpCiHappyScenario.timeouts.vitestTestMs
    );

    test(
      'WP_020: The Wallet Attestation is signed by its authorized Wallet Provider.',
      async () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });
        expect(clientAttestation, 'should parse the client attestation headers from PAR').toBeDefined();
        if (!clientAttestation) {
          throw new Error('PAR request is missing client attestation headers');
        }

        const { header: attestationHeader, payload: attestationPayload } = decodeJwt({
          jwt: clientAttestation.walletAttestationJwt,
          headerSchema: zWalletAttestationJwtHeaderV1_4,
          payloadSchema: zWalletAttestationJwtPayloadV1_4
        });

        expect(attestationHeader.x5c, 'Wallet Attestation should carry an X.509 certificate chain').not.toHaveLength(0);

        const certificates = attestationHeader.x5c.map((certificate, index) =>
          certificateFromBase64Der(certificate, `Wallet Attestation x5c[${index}]`)
        );
        const [leafCertificate] = certificates;
        if (!leafCertificate) {
          throw new Error('Wallet Attestation header is missing the leaf x5c certificate');
        }

        const validationDate = new Date(attestationPayload.iat * 1000);
        certificates.forEach((certificate, index) =>
          expectCertificateValidAt(certificate, validationDate, `Wallet Attestation x5c[${index}]`)
        );

        for (let index = 0; index < certificates.length - 1; index++) {
          const certificate = certificates[index];
          const issuerCertificate = certificates[index + 1];
          if (!certificate || !issuerCertificate) {
            throw new Error(`Wallet Attestation x5c chain is missing certificate at index ${index}`);
          }

          expectCertificateIssuedBy(certificate, issuerCertificate, `Wallet Attestation x5c[${index}]`);
        }

        const lastCertificate = certificates.at(-1);
        if (!lastCertificate) {
          throw new Error('Wallet Attestation x5c chain is empty');
        }

        const trustAnchorCertificate = trustAnchorCertificateFromConfig(config.global.trust_anchor_certificate);
        expectCertificateValidAt(trustAnchorCertificate, validationDate, 'Configured Trust Anchor certificate');
        expectCertificateIssuedBy(
          lastCertificate,
          trustAnchorCertificate,
          `Wallet Attestation x5c[${certificates.length - 1}]`
        );

        const walletProviderPublicKey = await importX509(leafCertificate.toString(), attestationHeader.alg);
        await expect(
          jwtVerify(clientAttestation.walletAttestationJwt, walletProviderPublicKey, {
            algorithms: [attestationHeader.alg],
            issuer: trimTrailingSlash(config['wallet-provider'].url)
          }),
          'Wallet Attestation signature should verify with the authorized Wallet Provider x5c leaf certificate'
        ).resolves.toBeDefined();
      },
      wpCiHappyScenario.timeouts.vitestTestMs
    );

    test(
      'WP_028: When no revocation check methods are supported, the Wallet Provider issues a Wallet Attestation with a defined expiration time and a short validity period.',
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
        expect(attestationPayload.exp, 'Wallet Attestation should carry an exp claim').toBeDefined();

        const maxValidityInSeconds = 24 * 60 * 60; // 86400 secondi
        if (!attestationPayload.exp || !attestationPayload.iat) {
          throw new Error('Wallet Attestation exp or iat claim is missing');
        }
        const validityDuration = attestationPayload.exp - attestationPayload.iat;

        // Verifica che exp sia successivo a iat
        expect(validityDuration, 'Wallet Attestation exp should be greater than iat').toBeGreaterThan(0);

        // Verifica che la finestra di validità (exp - iat) sia al massimo di 24 ore
        expect(
          validityDuration,
          'Wallet Attestation validity duration (exp - iat) should be at most 24 hours'
        ).toBeLessThanOrEqual(maxValidityInSeconds);
      },
      wpCiHappyScenario.timeouts.vitestTestMs
    );

    test(
      'WP_029a: Wallet Provider provides the Wallet Attestation in JWT format signed by the Wallet Provider, and confirming the structures defined in Wallet Attestation JWT.',
      async () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });
        expect(clientAttestation, 'should parse the client attestation headers from PAR').toBeDefined();
        if (!clientAttestation) {
          throw new Error('PAR request is missing client attestation headers');
        }

        const { header: attestationHeader, payload: attestationPayload } = decodeJwt({
          jwt: clientAttestation.walletAttestationJwt,
          headerSchema: zWalletAttestationJwtHeaderV1_4,
          payloadSchema: zWalletAttestationJwtPayloadV1_4
        });

        expect(attestationHeader.typ, 'Wallet Attestation typ should identify an OAuth client attestation').toBe(
          'oauth-client-attestation+jwt'
        );
        expect(attestationHeader.alg, 'Wallet Attestation alg should not be none').not.toBe('none');
        expect(attestationHeader.x5c, 'Wallet Attestation should carry an X.509 certificate chain').not.toHaveLength(0);

        const [leafCertificate] = attestationHeader.x5c;
        if (!leafCertificate) {
          throw new Error('Wallet Attestation header is missing the leaf x5c certificate');
        }

        const walletProviderPublicKey = await importX509(pemFromX5cCertificate(leafCertificate), attestationHeader.alg);
        await expect(
          jwtVerify(clientAttestation.walletAttestationJwt, walletProviderPublicKey, {
            algorithms: [attestationHeader.alg],
            issuer: trimTrailingSlash(config['wallet-provider'].url)
          }),
          'Wallet Attestation signature should verify with the Wallet Provider x5c certificate'
        ).resolves.toMatchObject({
          payload: expect.objectContaining({
            cnf: expect.objectContaining({ jwk: attestationPayload.cnf.jwk }),
            iss: trimTrailingSlash(config['wallet-provider'].url),
            sub: attestationPayload.sub
          })
        });
      },
      wpCiHappyScenario.timeouts.vitestTestMs
    );

    test(
      'WP_029b: The Wallet Attestation payload contains no personally identifiable information (PII) about the User.',
      () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });
        expect(clientAttestation, 'should parse the client attestation headers from PAR').toBeDefined();
        if (!clientAttestation) {
          throw new Error('PAR request is missing client attestation headers');
        }

        const { payload: attestationPayload } = decodeJwt({
          jwt: clientAttestation.walletAttestationJwt,
          payloadSchema: zWalletAttestationJwtPayloadV1_4
        });

        const unexpectedPayloadClaims = Object.keys(attestationPayload).filter(
          (claim) => !WALLET_ATTESTATION_NON_USER_PAYLOAD_CLAIMS.has(claim)
        );

        expect(
          unexpectedPayloadClaims,
          'Wallet Attestation payload should contain only non-user Wallet Attestation claims'
        ).toEqual([]);
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

  describe('WP_057', () => {
    let outcome: ScenarioOutcome;
    let events: ObservedEvent[];
    let offeredCredentialIdentifiers: string[];
    let credentialRequestedEvents: ObservedEvent[];
    let credentialIssuedEvents: ObservedEvent[];
    let credentialRequests: CredentialRequestV1_3[];
    let requestedCredentialIdentifiers: string[];
    let credentialProofJwts: string[];
    let credentialProofHeaders: ProofJwtHeaderV1_3[];
    let credentialProofPayloads: ProofJwtPayload[];

    beforeAll(async () => {
      const session = await runner.start(wp057Scenario.id);
      const credentialOfferUri = session.stimulus.type === 'credential-offer' ? session.stimulus.uri : '';

      try {
        await session.showInstructions();
        outcome = await session.awaitVerdict();
        events = session.events.all();

        const offerPayload = decodeCredentialOfferUri(credentialOfferUri);
        if (
          !Array.isArray(offerPayload.credential_configuration_ids) ||
          offerPayload.credential_configuration_ids.length !== 2 ||
          new Set(offerPayload.credential_configuration_ids).size !== 2
        ) {
          throw new Error('WP_057 Credential Offer must contain exactly 2 distinct credential_configuration_ids');
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
            'credential_offer.generated evidence is missing the credentialConfigurationIds required to assert WP_057'
          );
        }
        expect(credentialConfigurationIds).toEqual(offeredCredentialIdentifiers);

        credentialRequestedEvents = events
          .filter((event) => event.name === 'issuer.credential.requested')
          .sort((a, b) => a.monotonicMs - b.monotonicMs);
        if (credentialRequestedEvents.length !== 2) {
          throw new Error(
            `WP_057 requires exactly 2 issuer.credential.requested events, found ${credentialRequestedEvents.length}`
          );
        }

        if (new Set(credentialRequestedEvents.map((event) => event.requestId)).size !== 2) {
          throw new Error('WP_057 Credential Requests must be two separate HTTP requests with distinct request IDs');
        }

        credentialIssuedEvents = events
          .filter((event) => event.name === 'issuer.credential.issued')
          .sort((a, b) => a.monotonicMs - b.monotonicMs);
        if (credentialIssuedEvents.length !== 2) {
          throw new Error(
            `WP_057 requires exactly 2 issuer.credential.issued events, found ${credentialIssuedEvents.length}`
          );
        }

        credentialRequests = credentialRequestedEvents.map((event) => {
          const parseResult = zCredentialRequestV1_3.safeParse(event.diagnostic?.['body']);
          if (!parseResult.success) {
            throw new Error(
              `issuer.credential.requested evidence body is not a valid IT-Wallet v1.3/v1.4 Credential Request: ${parseResult.error.message}`
            );
          }
          return parseResult.data;
        });

        requestedCredentialIdentifiers = credentialRequests.map((request) => {
          if (!request.credential_identifier) {
            throw new Error('WP_057 Credential Request is missing credential_identifier');
          }
          return request.credential_identifier;
        });

        credentialProofJwts = credentialRequests.map((request) => {
          if (request.proofs.jwt.length !== 1) {
            throw new Error(
              `WP_057 Credential Request must carry exactly one proofs.jwt entry, preventing a batch-style request; found ${request.proofs.jwt.length}`
            );
          }
          return request.proofs.jwt[0];
        });

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
    }, wp057Scenario.timeouts.vitestTestMs);

    test('WP_057: the Credential Offer contains two distinct offered Digital Credentials.', () => {
      assertConformanceOutcome(outcome, { expected: 'PASS' });

      expect(offeredCredentialIdentifiers, 'Credential Offer should contain exactly 2 identifiers').toHaveLength(2);
      expect(new Set(offeredCredentialIdentifiers).size, 'Credential Offer identifiers should be distinct').toBe(2);
    });

    test('WP_057: the Wallet Instance sends a separate, DPoP-authenticated Credential Request for each offered credential.', () => {
      assertConformanceOutcome(outcome, { expected: 'PASS' });

      expect(credentialRequestedEvents, 'exactly two Credential Requests should be observed').toHaveLength(2);
      expect(
        new Set(credentialRequestedEvents.map((event) => event.requestId)).size,
        'the two Credential Requests should be two separate HTTP requests'
      ).toBe(2);

      for (const event of credentialRequestedEvents) {
        expect(event.diagnostic?.['endpoint'], 'each Credential Request should call /credential').toBe('/credential');
        expect(event.diagnostic?.['method'], 'each Credential Request should use POST').toBe('POST');

        const contentType = requiredDiagnosticString(event, 'contentType');
        expect(contentType.toLowerCase(), 'each Credential Request should use JSON content').toContain(
          'application/json'
        );

        expect(event.diagnostic?.['authorizationScheme'], 'each Credential Request should use DPoP authorization').toBe(
          'DPoP'
        );
        expect(
          requiredDiagnosticString(event, 'accessTokenSha256'),
          'each Credential Request evidence should include the access token hash'
        ).not.toHaveLength(0);
        expect(
          requiredDiagnosticString(event, 'dpopProof'),
          'each Credential Request should include a DPoP proof'
        ).not.toHaveLength(0);
      }
    });

    test('WP_057: each Credential Request is schema-valid and requests exactly one credential identifier with one proof, preventing a batch-style request.', () => {
      assertConformanceOutcome(outcome, { expected: 'PASS' });

      for (const request of credentialRequests) {
        expect(
          request.credential_identifier,
          'each Credential Request should carry exactly one credential_identifier'
        ).toBeTypeOf('string');
        expect(request.proofs.jwt, 'each Credential Request should carry exactly one proofs.jwt entry').toHaveLength(1);
      }
    });

    test('WP_057: the two Credential Requests, taken as a set, request exactly the two offered credential identifiers.', () => {
      assertConformanceOutcome(outcome, { expected: 'PASS' });

      expect(
        new Set(requestedCredentialIdentifiers).size,
        'the two Credential Requests should request distinct identifiers'
      ).toBe(2);
      expect(
        [...requestedCredentialIdentifiers].sort(),
        'the requested identifiers should equal the offered identifiers, independent of order'
      ).toEqual([...offeredCredentialIdentifiers].sort());
    });

    test('WP_057: each Credential Request proof JWT is well-formed and verifies against the public JWK declared in its header.', async () => {
      assertConformanceOutcome(outcome, { expected: 'PASS' });

      for (let index = 0; index < credentialProofJwts.length; index += 1) {
        const header = credentialProofHeaders[index];
        const payload = credentialProofPayloads[index];

        expect(header.jwk, 'proof JWT header should include a public JWK').toBeDefined();
        expect(header.jwk.kty, 'proof JWT key should not be symmetric').not.toBe('oct');
        expect(header.jwk.d, 'proof JWT header should not expose private key material').toBeUndefined();
        expect(payload.nonce, 'proof JWT should carry a non-empty nonce').not.toHaveLength(0);

        const publicKey = await importJWK(header.jwk as JWK, header.alg);
        await expect(
          jwtVerify(credentialProofJwts[index], publicKey),
          'proof JWT signature should verify with the declared public JWK'
        ).resolves.toBeDefined();
      }
    });

    test('WP_057: both Credential Requests are independently accepted, each producing a correlated issuer.credential.issued event.', () => {
      assertConformanceOutcome(outcome, { expected: 'PASS' });

      expect(credentialIssuedEvents, 'exactly two issuer.credential.issued events should be observed').toHaveLength(2);

      const requestedIds = credentialRequestedEvents.map((event) => event.requestId).sort();
      const issuedIds = credentialIssuedEvents.map((event) => event.requestId).sort();
      expect(issuedIds, 'issued events should correlate 1:1 with the requestId of the two Credential Requests').toEqual(
        requestedIds
      );

      for (const event of credentialIssuedEvents) {
        expect(event.diagnostic?.['statusCode'], 'each issued response should be HTTP 200').toBe(200);
        expect(event.diagnostic?.['responseKind'], 'each issued response should be immediate (non-deferred)').toBe(
          'immediate'
        );
      }
    });
  });

  describe('WP_017', () => {
    let outcome: ScenarioOutcome;
    let events: ObservedEvent[];

    beforeAll(async () => {
      const session = await runner.start(wp017Scenario.id);
      try {
        await session.showInstructions();
        outcome = await session.awaitVerdict();
        events = session.events.all();
      } finally {
        await session.stop();
      }
    }, wp017Scenario.timeouts.vitestTestMs);

    test(
      'WP_017: Wallet Instance rejects a Trust Anchor Entity Configuration key that does not match the configured out-of-band key.',
      () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        const entityConfigurationEvent = events.find(
          (event) => event.name === 'trust_anchor.entity_configuration.requested'
        );
        const faultAppliedEvent = events.find((event) => event.name === 'trust_anchor.fault.applied');

        expect(
          entityConfigurationEvent,
          'Wallet must request the Trust Anchor Entity Configuration before this scenario can pass'
        ).toBeDefined();
        expect(
          faultAppliedEvent,
          'The nonmatching signing-key fault must have been applied while serving the Trust Anchor Entity Configuration'
        ).toBeDefined();
        expect(faultAppliedEvent?.diagnostic?.['faultProfileType']).toBe(
          'entity-configuration-nonmatching-signing-key'
        );
        expect(faultAppliedEvent?.diagnostic?.['artifactHash']).toEqual(
          expect.stringMatching(/^sha256:[A-Za-z0-9_-]+$/)
        );
        expect(faultAppliedEvent?.diagnostic).not.toHaveProperty('jwt');
        expect(faultAppliedEvent?.diagnostic).not.toHaveProperty('jwk');

        expect(
          events.find((event) => event.name === 'issuer.par.requested'),
          'Wallet must not continue to PAR after rejecting the nonmatching Trust Anchor key'
        ).toBeUndefined();
      },
      wp017Scenario.timeouts.vitestTestMs
    );

    test('Cleanup: deactivating the Trust Anchor signing-key fault restores the nominal Entity Configuration key.', async () => {
      const discoveryUrl = new URL('/.well-known/openid-federation', config['trust-anchor'].url);
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
          `Unable to fetch Trust Anchor entity configuration (${response.statusCode ?? 'unknown'}): ${response.body}`
        );
      }

      const claims = decodeEntityConfiguration(response.body);
      expect(claims.jwks.keys, 'The Trust Anchor Entity Configuration must publish exactly one key').toHaveLength(1);
      expect(
        claims.jwks.keys[0]?.kid,
        'The Trust Anchor must stop publishing the ephemeral WP_017 fault key after cleanup'
      ).not.toBe('wp-017-nonmatching-trust-anchor-key');
    }, 10_000);
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

  describe('WP_050a', () => {
    let outcome: ScenarioOutcome;
    let events: ObservedEvent[];
    let credentialOfferUri: string;

    beforeAll(async () => {
      const session = await runner.start(wp050aMetadataPolicyScenario.id);

      try {
        await session.showInstructions();
        outcome = await session.awaitVerdict();
        events = session.events.all();
        credentialOfferUri = session.stimulus.type === 'credential-offer' ? session.stimulus.uri : '';
      } finally {
        await session.stop();
      }
    }, wp050aMetadataPolicyScenario.timeouts.vitestTestMs);

    test(
      'WP_050a: Wallet Instance rejects a Credential Issuer not authorized to issue the requested Digital Credential by metadata policy.',
      () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        const offerPayload = decodeCredentialOfferUri(credentialOfferUri);
        expect(offerPayload.credential_configuration_ids).toEqual([
          WP_050A_METADATA_POLICY_CREDENTIAL_CONFIGURATION_ID
        ]);

        const entityConfigurationEvent = events.find((event) => event.name === 'issuer.entity_configuration.requested');
        const trustAnchorFetchEvent = events.find((event) => event.name === 'federation.fetch.requested');

        expect(
          entityConfigurationEvent,
          'Wallet must request the Credential Issuer Entity Configuration before this scenario can pass'
        ).toBeDefined();
        expect(
          trustAnchorFetchEvent,
          'Wallet must fetch the Credential Issuer Subordinate Statement from the Trust Anchor before this scenario can pass'
        ).toBeDefined();
        if (!entityConfigurationEvent || !trustAnchorFetchEvent) {
          throw new Error('Missing issuer.entity_configuration.requested or federation.fetch.requested evidence');
        }

        const fetchSub = trustAnchorFetchEvent.diagnostic?.['sub'];
        expect(typeof fetchSub, 'Trust Anchor /fetch evidence should include the requested sub').toBe('string');
        if (typeof fetchSub !== 'string') {
          throw new Error('federation.fetch.requested evidence is missing the sub diagnostic');
        }
        expect(trimTrailingSlash(fetchSub), 'Trust Anchor /fetch sub should target the configured issuer').toBe(
          trimTrailingSlash(config['credential-issuer'].url)
        );

        expect(
          events.indexOf(trustAnchorFetchEvent),
          'Trust Anchor fetch must occur after the issuer Entity Configuration request'
        ).toBeGreaterThan(events.indexOf(entityConfigurationEvent));
      },
      wp050aMetadataPolicyScenario.timeouts.vitestTestMs
    );
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
    let originalTokenArtifact: TokenRequestArtifact;
    let refreshTokenArtifact: TokenRequestArtifact;
    let deferredCredentialRequestEvent: ObservedEvent;
    let deferredCredentialIssuedEvent: ObservedEvent;

    beforeAll(async () => {
      const session = await runner.start(wpDeferredScenario.id);
      const credentialOfferUri = session.stimulus.type === 'credential-offer' ? session.stimulus.uri : '';

      try {
        await session.showInstructions();
        outcome = await session.awaitVerdict();
        events = session.events.all();

        const offerPayload = decodeCredentialOfferUri(credentialOfferUri);
        if (!Array.isArray(offerPayload.credential_configuration_ids)) {
          throw new Error(
            'WP_Deferred Credential Offer must contain credential_configuration_ids to enable batch issuance'
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

        const tokenEvents = events.filter((event) => event.name === 'issuer.token.requested');
        if (tokenEvents.length !== 2) {
          throw new Error(
            `WP_Deferred must observe exactly two successful issuer.token.requested events: the authorization-code exchange and the refresh-token exchange. Found ${tokenEvents.length}.`
          );
        }

        const tokenArtifacts = tokenEvents.map((event, index): TokenRequestArtifact => {
          const context = `WP_Deferred Token Request ${index + 1}`;
          const tokenEndpoint = requiredDiagnosticString(event, 'endpoint');
          const requestUrl = `${config['credential-issuer'].url}${tokenEndpoint}`;
          const headers = toHeaders(event.diagnostic?.['headers'], context);

          let requestResult: ReturnType<typeof parseAccessTokenRequest>;
          try {
            requestResult = parseAccessTokenRequest({
              accessTokenRequest: diagnosticBodyRecord(event, context),
              request: {
                headers,
                method: 'POST' as HttpMethod,
                url: requestUrl
              }
            });
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            throw new Error(`${context} could not be parsed as an IT-Wallet v1.4 Token Request: ${message}`);
          }

          let dpopHeader: DpopJwtHeader;
          let dpopPayload: DpopJwtPayload;
          try {
            ({ header: dpopHeader, payload: dpopPayload } = decodeJwt({
              jwt: requestResult.dpop.jwt,
              headerSchema: zDpopJwtHeader,
              payloadSchema: zDpopJwtPayload
            }));
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            throw new Error(`${context} DPoP JWT could not be decoded: ${message}`);
          }

          let popHeader: ItWalletClientAttestationPopJwtHeader;
          let popPayload: ItWalletClientAttestationPopJwtPayload;
          try {
            ({ header: popHeader, payload: popPayload } = decodeJwt({
              jwt: requestResult.clientAttestation.clientAttestationPopJwt,
              headerSchema: zItWalletClientAttestationPopJwtHeader,
              payloadSchema: zItWalletClientAttestationPopJwtPayload
            }));
          } catch (error) {
            const message = error instanceof Error ? error.message : String(error);
            throw new Error(`${context} Wallet Attestation PoP JWT could not be decoded: ${message}`);
          }

          const walletAttestationCnfJwk = requireWalletAttestationCnfJwk(requestResult, context);

          return {
            dpopHeader,
            dpopPayload,
            event,
            headers,
            popHeader,
            popPayload,
            requestResult,
            requestUrl,
            walletAttestationCnfJwk
          };
        });

        const foundOriginalTokenArtifact = tokenArtifacts.find(
          (artifact) => artifact.requestResult.grant.grantType === 'authorization_code'
        );
        if (!foundOriginalTokenArtifact) {
          throw new Error('WP_Deferred is missing the initial authorization_code Token Request evidence');
        }
        originalTokenArtifact = foundOriginalTokenArtifact;

        const foundRefreshTokenArtifact = tokenArtifacts.find(
          (artifact) => artifact.requestResult.grant.grantType === 'refresh_token'
        );
        if (!foundRefreshTokenArtifact) {
          throw new Error('WP_Deferred is missing the refresh_token Token Request evidence');
        }
        refreshTokenArtifact = foundRefreshTokenArtifact;

        if (originalTokenArtifact.event.monotonicMs >= refreshTokenArtifact.event.monotonicMs) {
          throw new Error('WP_Deferred refresh_token Token Request must occur after the authorization_code exchange');
        }

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

        const foundDeferredEvent = events.find((event) => event.name === 'issuer.credential.deferred');
        if (!foundDeferredEvent) {
          throw new Error('Missing issuer.credential.deferred evidence required to assert WP_065-WP_068 requirements');
        }

        const foundDeferredCredentialRequestEvent = events.find(
          (event) => event.name === 'issuer.deferred_credential.requested'
        );
        if (!foundDeferredCredentialRequestEvent) {
          throw new Error('Missing issuer.deferred_credential.requested evidence required to assert WP_066a/WP_068');
        }
        deferredCredentialRequestEvent = foundDeferredCredentialRequestEvent;

        const foundDeferredCredentialIssuedEvent = events.find(
          (event) => event.name === 'issuer.deferred_credential.issued'
        );
        if (!foundDeferredCredentialIssuedEvent) {
          throw new Error('Missing issuer.deferred_credential.issued evidence required to assert WP_066/WP_068');
        }
        deferredCredentialIssuedEvent = foundDeferredCredentialIssuedEvent;
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
        expect(intervalSeconds, 'interval must match the two-minute Access Token lifetime for WP_068').toBe(120);
        expect(
          requiredDiagnosticString(deferredEvent, 'transactionIdSha256'),
          'Deferred response evidence must include a non-empty transaction_id hash'
        ).not.toHaveLength(0);
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
        expect(
          requiredDiagnosticString(issuedEvent, 'notificationIdSha256'),
          'issuer.deferred_credential.issued evidence must include a non-empty notification_id hash'
        ).not.toHaveLength(0);

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

    test(
      'WP_068: Wallet Instance requests a refreshed DPoP-bound Access Token with grant_type=refresh_token before retrieving deferred credentials.',
      async () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        expect(refreshTokenArtifact.event.diagnostic?.['endpoint'], 'Refresh Token Request should call /token').toBe(
          '/token'
        );

        const contentType = refreshTokenArtifact.headers.get('content-type');
        expect(contentType, 'Refresh Token Request should include a Content-Type header').not.toBeNull();
        expect(contentType?.toLowerCase(), 'Refresh Token Request should use form-urlencoded content').toContain(
          'application/x-www-form-urlencoded'
        );

        expect(refreshTokenArtifact.requestResult.grant.grantType, 'parsed refresh grant should be refresh_token').toBe(
          'refresh_token'
        );
        if (refreshTokenArtifact.requestResult.grant.grantType !== 'refresh_token') {
          throw new Error('Expected the second Token Request to use the refresh_token grant');
        }
        expect(
          refreshTokenArtifact.requestResult.grant.refreshToken,
          'Refresh Token Request should include a non-empty refresh_token value'
        ).not.toHaveLength(0);
        expect(refreshTokenArtifact.requestResult.accessTokenRequest.grant_type).toBe('refresh_token');

        expect(refreshTokenArtifact.headers.get('DPoP'), 'Refresh Token Request should include DPoP').not.toBeNull();
        expect(
          refreshTokenArtifact.headers.get('OAuth-Client-Attestation'),
          'Refresh Token Request should include OAuth-Client-Attestation'
        ).not.toBeNull();
        expect(
          refreshTokenArtifact.headers.get('OAuth-Client-Attestation-PoP'),
          'Refresh Token Request should include OAuth-Client-Attestation-PoP'
        ).not.toBeNull();

        expect(refreshTokenArtifact.dpopHeader.typ, 'Refresh DPoP JWT typ should be dpop+jwt').toBe('dpop+jwt');
        expect(refreshTokenArtifact.dpopHeader.alg, 'Refresh DPoP JWT alg should not be none').not.toBe('none');
        expect(
          refreshTokenArtifact.dpopHeader.jwk,
          'Refresh DPoP JWT header should include a public JWK'
        ).toBeDefined();
        expect(refreshTokenArtifact.dpopHeader.jwk.kty, 'Refresh DPoP JWK should not be symmetric').not.toBe('oct');
        expect(
          refreshTokenArtifact.dpopHeader.jwk.d,
          'Refresh DPoP JWK should not expose private key material'
        ).toBeUndefined();

        const publicKey = await importJWK(
          refreshTokenArtifact.dpopHeader.jwk as JWK,
          refreshTokenArtifact.dpopHeader.alg
        );
        await expect(
          jwtVerify(refreshTokenArtifact.requestResult.dpop.jwt, publicKey),
          'Refresh DPoP proof signature should verify with the declared public JWK'
        ).resolves.toBeDefined();

        expect(refreshTokenArtifact.dpopPayload.htm, 'Refresh DPoP proof should be bound to POST').toBe('POST');
        expect(refreshTokenArtifact.dpopPayload.htu, 'Refresh DPoP proof should target the Token Endpoint URL').toBe(
          htuFromRequestUrl(refreshTokenArtifact.requestUrl)
        );
        expectJwtIatFresh(refreshTokenArtifact.dpopPayload.iat, refreshTokenArtifact.event, 'Refresh DPoP proof');
        expect(
          refreshTokenArtifact.dpopPayload.jti,
          'Refresh DPoP proof should carry a non-empty jti'
        ).not.toHaveLength(0);

        expect(
          refreshTokenArtifact.popHeader.typ,
          'Refresh PoP JWT typ should identify OAuth client attestation PoP'
        ).toBe('oauth-client-attestation-pop+jwt');
        expect(refreshTokenArtifact.popHeader.alg, 'Refresh PoP JWT alg should be allowed by IT-Wallet').toBeOneOf([
          ...IT_WALLET_CLIENT_ATTESTATION_POP_ALLOWED_ALG_VALUES
        ]);
        await expect(
          verifyClientAttestationPopJwt({
            authorizationServer: config['credential-issuer'].url,
            callbacks: { verifyJwt: verifyJwtWithJwk },
            clientAttestationPopJwt: refreshTokenArtifact.requestResult.clientAttestation.clientAttestationPopJwt,
            clientAttestationPublicJwk: refreshTokenArtifact.walletAttestationCnfJwk
          }),
          'Refresh PoP JWT should verify against the refresh Wallet Attestation cnf.jwk'
        ).resolves.toBeDefined();

        expect(
          refreshTokenArtifact.event.monotonicMs,
          'Refresh Token Request should occur before the Deferred Credential Request'
        ).toBeLessThan(deferredCredentialRequestEvent.monotonicMs);
        expect(
          refreshTokenArtifact.event.monotonicMs,
          'Refresh Token Request should occur before deferred credentials are issued'
        ).toBeLessThan(deferredCredentialIssuedEvent.monotonicMs);
      },
      wpDeferredScenario.timeouts.vitestTestMs
    );

    test(
      'WP_068a: Wallet Instance creates fresh DPoP and Wallet Attestation PoP JWT instances for the Refresh Token Request.',
      () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        expect(
          refreshTokenArtifact.requestResult.dpop.jwt,
          'Refresh Token Request DPoP compact JWT should differ from the original Token Request DPoP JWT'
        ).not.toBe(originalTokenArtifact.requestResult.dpop.jwt);
        expect(
          refreshTokenArtifact.dpopPayload.jti,
          'Refresh Token Request DPoP jti should differ from the original Token Request DPoP jti'
        ).not.toBe(originalTokenArtifact.dpopPayload.jti);
        expectJwtIatFresh(originalTokenArtifact.dpopPayload.iat, originalTokenArtifact.event, 'Original DPoP proof');
        expectJwtIatFresh(refreshTokenArtifact.dpopPayload.iat, refreshTokenArtifact.event, 'Refresh DPoP proof');

        expect(
          refreshTokenArtifact.requestResult.clientAttestation.clientAttestationPopJwt,
          'Refresh Token Request Wallet Attestation PoP compact JWT should differ from the original Token Request PoP JWT'
        ).not.toBe(originalTokenArtifact.requestResult.clientAttestation.clientAttestationPopJwt);
        expect(
          refreshTokenArtifact.popPayload.jti,
          'Refresh Token Request PoP jti should differ from the original Token Request PoP jti'
        ).not.toBe(originalTokenArtifact.popPayload.jti);
        expectJwtIatFresh(originalTokenArtifact.popPayload.iat, originalTokenArtifact.event, 'Original PoP proof');
        expectJwtIatFresh(refreshTokenArtifact.popPayload.iat, refreshTokenArtifact.event, 'Refresh PoP proof');
      },
      wpDeferredScenario.timeouts.vitestTestMs
    );

    test(
      'WP_068b: Wallet Instance reuses the original DPoP key and Wallet Attestation cnf.jwk for the Refresh Token Request.',
      async () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        const originalDpopThumbprint = await calculateJwkThumbprint(originalTokenArtifact.dpopHeader.jwk as JWK);
        const refreshDpopThumbprint = await calculateJwkThumbprint(refreshTokenArtifact.dpopHeader.jwk as JWK);
        expect(
          refreshDpopThumbprint,
          'Refresh Token Request DPoP JWK must match the original Token Request DPoP JWK'
        ).toBe(originalDpopThumbprint);

        const originalAttestationThumbprint = await calculateJwkThumbprint(
          originalTokenArtifact.walletAttestationCnfJwk
        );
        const refreshAttestationThumbprint = await calculateJwkThumbprint(refreshTokenArtifact.walletAttestationCnfJwk);
        expect(
          refreshAttestationThumbprint,
          'Refresh Token Request Wallet Attestation cnf.jwk must match the original Token Request Wallet Attestation cnf.jwk'
        ).toBe(originalAttestationThumbprint);

        await expect(
          verifyClientAttestationPopJwt({
            authorizationServer: config['credential-issuer'].url,
            callbacks: { verifyJwt: verifyJwtWithJwk },
            clientAttestationPopJwt: originalTokenArtifact.requestResult.clientAttestation.clientAttestationPopJwt,
            clientAttestationPublicJwk: originalTokenArtifact.walletAttestationCnfJwk
          }),
          'Original Token Request PoP JWT should verify against the original Wallet Attestation cnf.jwk'
        ).resolves.toBeDefined();

        await expect(
          verifyClientAttestationPopJwt({
            authorizationServer: config['credential-issuer'].url,
            callbacks: { verifyJwt: verifyJwtWithJwk },
            clientAttestationPopJwt: refreshTokenArtifact.requestResult.clientAttestation.clientAttestationPopJwt,
            clientAttestationPublicJwk: originalTokenArtifact.walletAttestationCnfJwk
          }),
          'Refresh Token Request PoP JWT should verify against the original Wallet Attestation cnf.jwk'
        ).resolves.toBeDefined();
      },
      wpDeferredScenario.timeouts.vitestTestMs
    );
  });

  describe('WP_Reissuance', () => {
    let outcome: ScenarioOutcome;
    let events: ObservedEvent[];
    let statusListJwt: string;

    beforeAll(async () => {
      const session = await runner.start(wpCredentialReissuanceScenario.id);
      try {
        await session.showInstructions();

        const firstIssuedEvent = await session.events.waitFor('issuer.credential.issued', {
          timeoutMs: wpCredentialReissuanceScenario.timeouts.protocolStepMs,
          signal: session.abortSignal
        });
        const firstTokenEvent = nthEvent(session.events.all(), 'issuer.token.requested', 0);
        const expiryBoundaryMs =
          Date.parse(firstTokenEvent.timestamp) + WP_CREDENTIAL_REISSUANCE_INITIAL_TOKEN_TTL_SECONDS * 1000;
        const remainingMs = expiryBoundaryMs + 1_000 - Date.now();
        if (remainingMs > 0) {
          await sleep(remainingMs, undefined, { signal: session.abortSignal });
        }

        await issuerFaultController.activateIssuerConfig({
          scenarioId: session.correlationId,
          config: {
            batchIssuanceByDeferred: wpCredentialReissuanceUpdatedIssuerConfig.batchIssuanceByDeferred,
            accessTokenTtlSeconds: wpCredentialReissuanceUpdatedIssuerConfig.accessTokenTtlSeconds,
            refreshTokenTtlSeconds: wpCredentialReissuanceUpdatedIssuerConfig.refreshTokenTtlSeconds,
            statusList: {
              bits: wpCredentialReissuanceUpdatedIssuerConfig.statusList.bits,
              values: [...wpCredentialReissuanceUpdatedIssuerConfig.statusList.values]
            }
          }
        });

        await waitForUpdatedStatusListEvent(
          session.events,
          firstIssuedEvent,
          session.abortSignal,
          wpCredentialReissuanceScenario.timeouts.protocolStepMs
        );

        outcome = await session.awaitVerdict();
        events = session.events.all();
        statusListJwt = await fetchStatusListJwt(
          requiredDiagnosticString(nthEvent(events, 'issuer.credential.issued', 0), 'statusListUri')
        );
      } finally {
        await session.stop();
      }
    }, wpCredentialReissuanceScenario.timeouts.vitestTestMs);

    test(
      'WP_070: Wallet Instance detects UPDATE for the stored Digital Credential in the Status List.',
      async () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        const firstIssuedEvent = nthEvent(events, 'issuer.credential.issued', 0);
        const statusListEvent = events.find(isUpdatedStatusListEvent);
        expect(statusListEvent, 'Updated Status List request evidence must be observed').toBeDefined();
        if (!statusListEvent) {
          throw new Error('Missing issuer.status_list.requested evidence for the updated Status List');
        }

        const statusListUri = requiredDiagnosticString(firstIssuedEvent, 'statusListUri');
        expect(statusListEvent.diagnostic?.['endpoint'], 'Wallet must request the Status List endpoint').toBe(
          new URL(statusListUri).pathname
        );
        expect(statusListEvent.monotonicMs, 'Status List request must happen after first issuance').toBeGreaterThan(
          firstIssuedEvent.monotonicMs
        );
        expect(
          statusListEvent.monotonicMs,
          'Status List request must happen before refresh failure/new issuance activity'
        ).toBeLessThan(nthEvent(events, 'issuer.token.failed', 0).monotonicMs);

        const { header } = decodeJwtHeader({ jwt: statusListJwt });
        const { payload } = decodeJwt({ jwt: statusListJwt });
        expect(header.typ, 'Status List JWT typ must identify a Status List Token').toBe('statuslist+jwt');
        expect(Array.isArray(header.x5c), 'Status List JWT must carry an x5c chain').toBe(true);
        if (!Array.isArray(header.x5c) || header.x5c.length === 0) {
          throw new Error('Status List JWT header is missing x5c');
        }

        const leafCertificate = certificateFromBase64Der(header.x5c[0], 'Status List x5c[0]');
        const publicKey = await importX509(leafCertificate.toString(), header.alg);
        await expect(
          jwtVerify(statusListJwt, publicKey, {
            algorithms: [header.alg],
            issuer: config['credential-issuer'].url,
            subject: statusListUri
          }),
          'Status List JWT signature and iss/sub claims must verify'
        ).resolves.toBeDefined();

        expect(payload.iss, 'Status List issuer must be the Credential Issuer').toBe(config['credential-issuer'].url);
        expect(payload.sub, 'Status List subject must be the referenced Status List URI').toBe(statusListUri);
        expect(payload.exp, 'Status List expiry must be numeric').toBeTypeOf('number');
        expect(payload.iat, 'Status List issued-at must be numeric').toBeTypeOf('number');
        expect(Number(payload.exp), 'Status List exp must be after iat').toBeGreaterThan(Number(payload.iat));

        const statusList = payload.status_list as { bits?: unknown; lst?: unknown } | undefined;
        expect(statusList?.bits, 'Status List must use four-bit statuses').toBe(4);
        expect(typeof statusList?.lst, 'Status List must carry a compressed list').toBe('string');
        if (statusList?.bits !== 4 || typeof statusList.lst !== 'string') {
          throw new Error('Status List JWT payload is missing a valid four-bit status_list');
        }

        expect(
          getStatusFromCompressedStatusList(statusList.lst, statusList.bits, WP_CREDENTIAL_REISSUANCE_STATUS_INDEX),
          'Credential index 1 must resolve to UPDATE'
        ).toBe(WP_CREDENTIAL_REISSUANCE_UPDATED_STATUS);
      },
      wpCredentialReissuanceScenario.timeouts.vitestTestMs
    );

    test(
      'WP_067: Wallet Instance fails expired Refresh Token exchange and starts a new issuance flow.',
      () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        const firstTokenEvent = nthEvent(events, 'issuer.token.requested', 0);
        const failedTokenEvent = nthEvent(events, 'issuer.token.failed', 0);
        expect(failedTokenEvent.diagnostic?.['grantType'], 'Failed Token request must use refresh_token').toBe(
          'refresh_token'
        );
        expect(failedTokenEvent.diagnostic?.['error'], 'Refresh failure must be invalid_grant').toBe('invalid_grant');
        expect(failedTokenEvent.diagnostic?.['statusCode'], 'Refresh failure must be HTTP 400').toBe(400);

        const refreshExpiryBoundaryMs =
          Date.parse(firstTokenEvent.timestamp) + WP_CREDENTIAL_REISSUANCE_INITIAL_TOKEN_TTL_SECONDS * 1000;
        expect(
          Date.parse(failedTokenEvent.timestamp),
          'Refresh Token must be expired when the wallet presents it'
        ).toBeGreaterThanOrEqual(refreshExpiryBoundaryMs);

        const failedResponse = findHttpResponseSentEvent(events, failedTokenEvent.requestId);
        expect(failedResponse?.http.statusCode, 'Token endpoint must reject the expired Refresh Token').toBe(400);

        const secondParEvent = nthEvent(events, 'issuer.par.requested', 1);
        expect(secondParEvent.monotonicMs, 'A new PAR request must start after the failed refresh').toBeGreaterThan(
          failedTokenEvent.monotonicMs
        );

        const secondTokenEvent = nthEvent(events, 'issuer.token.requested', 1);
        const credentialRequestsBetweenFailureAndNewToken = events
          .filter((event) => event.name === 'issuer.credential.requested')
          .filter(
            (event) =>
              event.monotonicMs > failedTokenEvent.monotonicMs && event.monotonicMs < secondTokenEvent.monotonicMs
          );
        expect(
          credentialRequestsBetweenFailureAndNewToken,
          'No expired token may be accepted at the Credential Endpoint before the new Token exchange'
        ).toHaveLength(0);
      },
      wpCredentialReissuanceScenario.timeouts.vitestTestMs
    );

    test(
      'WP_071b: Wallet Instance performs a second authorization-code flow after the failed refresh.',
      () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        const failedTokenEvent = nthEvent(events, 'issuer.token.failed', 0);
        const parEvents = eventsByName(events, 'issuer.par.requested');
        const authorizationEvents = eventsByName(events, 'issuer.authorization.requested');
        const tokenEvents = eventsByName(events, 'issuer.token.requested');
        expect(parEvents.length, 'Two distinct PAR requests must be observed').toBeGreaterThanOrEqual(2);
        expect(
          authorizationEvents.length,
          'Two Authorization Endpoint requests must be observed'
        ).toBeGreaterThanOrEqual(2);
        expect(
          tokenEvents.length,
          'Two successful authorization-code Token exchanges must be observed'
        ).toBeGreaterThanOrEqual(2);

        const firstParRequestUri = requiredDiagnosticString(parEvents[0], 'requestUri');
        const secondParRequestUri = requiredDiagnosticString(parEvents[1], 'requestUri');
        expect(secondParRequestUri, 'Second PAR request_uri must be distinct').not.toBe(firstParRequestUri);

        expect(
          authorizationEvents[1].monotonicMs,
          'Second Authorization request must happen after failed refresh'
        ).toBeGreaterThan(failedTokenEvent.monotonicMs);
        expect(
          authorizationEvents[1].diagnostic?.['requestUri'],
          'Second Authorization must use second request_uri'
        ).toBe(secondParRequestUri);

        const firstTokenRequest = parseTokenRequestFromEvent(tokenEvents[0], config['credential-issuer'].url);
        const secondTokenRequest = parseTokenRequestFromEvent(tokenEvents[1], config['credential-issuer'].url);
        expect(secondTokenRequest.grant.grantType, 'Second Token exchange must use authorization_code').toBe(
          'authorization_code'
        );
        if (
          firstTokenRequest.grant.grantType !== 'authorization_code' ||
          secondTokenRequest.grant.grantType !== 'authorization_code'
        ) {
          throw new Error('Expected both successful Token exchanges to use authorization_code');
        }
        expect(secondTokenRequest.grant.code, 'Second authorization code must be distinct').not.toBe(
          firstTokenRequest.grant.code
        );
      },
      wpCredentialReissuanceScenario.timeouts.vitestTestMs
    );

    test(
      'WP_072: Wallet Instance uses the new DPoP-bound Access Token at the Credential Endpoint and retrieves the updated credential.',
      async () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        const tokenEvents = eventsByName(events, 'issuer.token.requested');
        const nonceEvents = eventsByName(events, 'issuer.nonce.requested');
        const credentialEvents = eventsByName(events, 'issuer.credential.requested');
        const issuedEvents = eventsByName(events, 'issuer.credential.issued');
        const secondTokenEvent = tokenEvents[1];
        const secondNonceEvent = nonceEvents[1];
        const firstCredentialEvent = credentialEvents[0];
        const secondCredentialEvent = credentialEvents[1];
        const firstIssuedEvent = issuedEvents[0];
        const secondIssuedEvent = issuedEvents[1];
        if (
          !secondTokenEvent ||
          !secondNonceEvent ||
          !firstCredentialEvent ||
          !secondCredentialEvent ||
          !firstIssuedEvent ||
          !secondIssuedEvent
        ) {
          throw new Error('Missing second-flow Token, Nonce, Credential Request, or issuance evidence');
        }

        expect(secondCredentialEvent.diagnostic?.['authorizationScheme']).toBe('DPoP');
        expect(secondCredentialEvent.diagnostic?.['endpoint']).toBe('/credential');
        expect(
          secondCredentialEvent.monotonicMs,
          'Second Credential Request must follow second Token exchange'
        ).toBeGreaterThan(secondTokenEvent.monotonicMs);
        expect(
          secondIssuedEvent.monotonicMs,
          'Second issuance must be correlated to the second request'
        ).toBeGreaterThan(secondCredentialEvent.monotonicMs);

        const firstAccessTokenHash = requiredDiagnosticString(firstCredentialEvent, 'accessTokenSha256');
        const secondAccessTokenHash = requiredDiagnosticString(secondCredentialEvent, 'accessTokenSha256');
        expect(secondAccessTokenHash, 'Second Credential Request must use a fresh access token').not.toBe(
          firstAccessTokenHash
        );

        const secondCredentialRequest = parseCredentialRequestFromEvent(secondCredentialEvent);
        const [proofJwt] = secondCredentialRequest.proofs.jwt;
        if (!proofJwt) {
          throw new Error('Second Credential Request is missing holder-binding proof JWT');
        }

        const credentialDpopJwt = requiredDiagnosticString(secondCredentialEvent, 'dpopProof');
        const { header: credentialDpopHeader, payload: credentialDpopPayload } = decodeJwt({
          jwt: credentialDpopJwt,
          headerSchema: zDpopJwtHeader,
          payloadSchema: zDpopJwtPayload
        });
        const { header: proofHeader, payload: proofPayload } = decodeJwt({
          jwt: proofJwt,
          headerSchema: zProofJwtHeaderV1_3,
          payloadSchema: zProofJwtPayload
        });

        const credentialRequestUrl = `${config['credential-issuer'].url}${requiredDiagnosticString(
          secondCredentialEvent,
          'endpoint'
        )}`;
        const dpopPublicKey = await importJWK(credentialDpopHeader.jwk as JWK, credentialDpopHeader.alg);
        await expect(
          jwtVerify(credentialDpopJwt, dpopPublicKey),
          'Second Credential DPoP proof must verify'
        ).resolves.toBeDefined();
        expect(credentialDpopPayload.htm, 'Second Credential DPoP proof must bind POST').toBe('POST');
        expect(credentialDpopPayload.htu, 'Second Credential DPoP proof must bind the Credential Endpoint URL').toBe(
          htuFromRequestUrl(credentialRequestUrl)
        );
        expect(credentialDpopPayload.iat, 'Second Credential DPoP proof must carry iat').toBeTypeOf('number');
        expect(credentialDpopPayload.jti, 'Second Credential DPoP proof must carry jti').not.toHaveLength(0);
        expect(credentialDpopPayload.ath, 'Second Credential DPoP ath must match the new access token').toBe(
          secondAccessTokenHash
        );

        const secondTokenRequest = parseTokenRequestFromEvent(secondTokenEvent, config['credential-issuer'].url);
        const { header: secondTokenDpopHeader } = decodeJwt({
          jwt: secondTokenRequest.dpop.jwt,
          headerSchema: zDpopJwtHeader,
          payloadSchema: zDpopJwtPayload
        });
        await expect(
          calculateJwkThumbprint(credentialDpopHeader.jwk as JWK),
          'Credential Request DPoP key must match the second Token Request DPoP key'
        ).resolves.toBe(await calculateJwkThumbprint(secondTokenDpopHeader.jwk as JWK));

        const proofPublicKey = await importJWK(proofHeader.jwk as JWK, proofHeader.alg);
        await expect(
          jwtVerify(proofJwt, proofPublicKey),
          'Holder-binding proof JWT must verify'
        ).resolves.toBeDefined();
        const secondNonceHash = requiredDiagnosticString(secondNonceEvent, 'cNonceSha256');
        expect(sha256Base64Url(proofPayload.nonce), 'Holder-binding proof must use the second nonce').toBe(
          secondNonceHash
        );
        expect(secondNonceHash, 'Second nonce must be fresh').not.toBe(
          requiredDiagnosticString(nonceEvents[0], 'cNonceSha256')
        );

        expect(
          requiredDiagnosticString(secondIssuedEvent, 'responseHash'),
          'Updated credential response hash must be present'
        ).not.toHaveLength(0);
        expect(
          requiredDiagnosticString(secondIssuedEvent, 'responseHash'),
          'Second credential response must be newly issued'
        ).not.toBe(requiredDiagnosticString(firstIssuedEvent, 'responseHash'));
      },
      wpCredentialReissuanceScenario.timeouts.vitestTestMs
    );
  });

  describe('WP_Reissuance_RefreshAccessToken', () => {
    let outcome: ScenarioOutcome;
    let events: ObservedEvent[];
    let statusListJwt: string;

    beforeAll(async () => {
      const session = await runner.start(wpCredentialReissuanceRefreshAccessTokenScenario.id);
      try {
        await session.showInstructions();

        const firstIssuedEvent = await session.events.waitFor('issuer.credential.issued', {
          timeoutMs: wpCredentialReissuanceRefreshAccessTokenScenario.timeouts.protocolStepMs,
          signal: session.abortSignal
        });
        const firstTokenEvent = nthEvent(session.events.all(), 'issuer.token.requested', 0);
        const originalAccessTokenExpMs = requiredDiagnosticNumber(firstTokenEvent, 'accessTokenExp') * 1000;
        const originalRefreshTokenExpMs = requiredDiagnosticNumber(firstTokenEvent, 'refreshTokenExp') * 1000;
        const nominalStatusListExpMs = latestObservedNominalStatusListExpiryMs(session.events.all());
        const transitionBoundaryMs =
          Math.max(originalAccessTokenExpMs, nominalStatusListExpMs ?? 0) + STATUS_LIST_CACHE_CLOCK_SKEW_MS;
        await waitUntilMs(transitionBoundaryMs, session.abortSignal);

        if (originalRefreshTokenExpMs <= Date.now() + STATUS_LIST_CACHE_CLOCK_SKEW_MS) {
          throw new Error(
            'Inconclusive WP_071a setup: the original Refresh Token expired before the UPDATE transition boundary.'
          );
        }

        await issuerFaultController.activateIssuerConfig({
          scenarioId: session.correlationId,
          config: {
            batchIssuanceByDeferred:
              wpCredentialReissuanceRefreshAccessTokenUpdatedIssuerConfig.batchIssuanceByDeferred,
            accessTokenTtlSeconds: wpCredentialReissuanceRefreshAccessTokenUpdatedIssuerConfig.accessTokenTtlSeconds,
            refreshTokenTtlSeconds: wpCredentialReissuanceRefreshAccessTokenUpdatedIssuerConfig.refreshTokenTtlSeconds,
            statusList: {
              bits: wpCredentialReissuanceRefreshAccessTokenUpdatedIssuerConfig.statusList.bits,
              values: [...wpCredentialReissuanceRefreshAccessTokenUpdatedIssuerConfig.statusList.values]
            }
          }
        });

        await waitForUpdatedStatusListEvent(
          session.events,
          firstIssuedEvent,
          session.abortSignal,
          wpCredentialReissuanceRefreshAccessTokenScenario.timeouts.protocolStepMs
        );

        outcome = await session.awaitVerdict();
        events = session.events.all();
        statusListJwt = await fetchStatusListJwt(
          requiredDiagnosticString(nthEvent(events, 'issuer.credential.issued', 0), 'statusListUri')
        );
      } finally {
        await session.stop();
      }
    }, wpCredentialReissuanceRefreshAccessTokenScenario.timeouts.vitestTestMs);

    test(
      'WP_071a: Wallet Instance uses a valid Refresh Token to obtain a new DPoP-bound Access Token for credential re-issuance.',
      async () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        const firstIssuedEvent = nthEvent(events, 'issuer.credential.issued', 0);
        const secondIssuedEvent = nthEvent(events, 'issuer.credential.issued', 1);
        const updatedStatusListEvent = events.find(isUpdatedStatusListEvent);
        expect(updatedStatusListEvent, 'Updated Status List request evidence must be observed').toBeDefined();
        if (!updatedStatusListEvent) {
          throw new Error('Missing issuer.status_list.requested evidence for the updated Status List');
        }

        expect(
          updatedStatusListEvent.monotonicMs,
          'Updated Status List request must happen after initial issuance'
        ).toBeGreaterThan(firstIssuedEvent.monotonicMs);

        const { payload: statusListPayload } = decodeJwt({ jwt: statusListJwt });
        const statusList = statusListPayload.status_list as { bits?: unknown; lst?: unknown } | undefined;
        expect(statusList?.bits, 'Status List must use four-bit statuses').toBe(4);
        expect(typeof statusList?.lst, 'Status List must carry a compressed list').toBe('string');
        if (statusList?.bits !== 4 || typeof statusList.lst !== 'string') {
          throw new Error('Status List JWT payload is missing a valid four-bit status_list');
        }
        expect(
          getStatusFromCompressedStatusList(statusList.lst, statusList.bits, WP_CREDENTIAL_REISSUANCE_STATUS_INDEX),
          'Credential index 1 must resolve to UPDATE'
        ).toBe(WP_CREDENTIAL_REISSUANCE_UPDATED_STATUS);

        const tokenEvents = eventsByName(events, 'issuer.token.requested');
        expect(tokenEvents, 'Exactly two successful Token Endpoint exchanges must be observed').toHaveLength(2);
        const [initialTokenEvent, refreshTokenEvent] = tokenEvents;
        if (!initialTokenEvent || !refreshTokenEvent) {
          throw new Error('Missing initial or refresh Token exchange evidence');
        }
        expect(initialTokenEvent.diagnostic?.['grantType'], 'Initial Token exchange must use authorization_code').toBe(
          'authorization_code'
        );
        expect(refreshTokenEvent.diagnostic?.['grantType'], 'Second Token exchange must use refresh_token').toBe(
          'refresh_token'
        );
        expect(refreshTokenEvent.diagnostic?.['tokenType'], 'Refresh exchange must return a DPoP token').toBe('DPoP');
        expect(eventsByName(events, 'issuer.token.failed'), 'Refresh exchange must emit no Token failure').toHaveLength(
          0
        );
        expect(
          refreshTokenEvent.monotonicMs,
          'Refresh Token exchange must happen after updated Status List retrieval'
        ).toBeGreaterThan(updatedStatusListEvent.monotonicMs);

        const originalAccessTokenExp = requiredDiagnosticNumber(initialTokenEvent, 'accessTokenExp');
        const originalRefreshTokenExp = requiredDiagnosticNumber(initialTokenEvent, 'refreshTokenExp');
        expect(
          Date.parse(refreshTokenEvent.timestamp),
          'Refresh Token exchange must occur at or after the original Access Token signed expiry'
        ).toBeGreaterThanOrEqual(originalAccessTokenExp * 1000);
        expect(
          Date.parse(refreshTokenEvent.timestamp),
          'Refresh Token exchange must occur before the original Refresh Token signed expiry'
        ).toBeLessThan(originalRefreshTokenExp * 1000);
        expect(
          originalRefreshTokenExp * 1000 - Date.parse(initialTokenEvent.timestamp),
          'Original Refresh Token lifetime must be long enough for WP_071a'
        ).toBeGreaterThanOrEqual(WP_CREDENTIAL_REISSUANCE_INITIAL_REFRESH_TOKEN_TTL_SECONDS * 1000 - 1_000);

        const initialTokenRequest = parseTokenRequestFromEvent(initialTokenEvent, config['credential-issuer'].url);
        const refreshTokenRequest = parseTokenRequestFromEvent(refreshTokenEvent, config['credential-issuer'].url);
        expect(refreshTokenRequest.grant.grantType, 'Refresh exchange must parse as refresh_token').toBe(
          'refresh_token'
        );
        if (refreshTokenRequest.grant.grantType !== 'refresh_token') {
          throw new Error('Expected the second Token Request to use the refresh_token grant');
        }

        const refreshBody = refreshTokenEvent.diagnostic?.['body'] as Record<string, unknown>;
        expect(refreshBody['grant_type'], 'Refresh Token Request form must use grant_type=refresh_token').toBe(
          'refresh_token'
        );
        expect(refreshBody['refresh_token'], 'Refresh Token Request form must carry refresh_token').toBeTypeOf(
          'string'
        );
        expect(refreshBody['code'], 'Refresh Token Request form must not carry code').toBeUndefined();
        expect(refreshBody['code_verifier'], 'Refresh Token Request form must not carry code_verifier').toBeUndefined();
        expect(refreshBody['redirect_uri'], 'Refresh Token Request form must not carry redirect_uri').toBeUndefined();
        expect(refreshTokenEvent.diagnostic?.['method'], 'Refresh Token Request must use POST').toBe('POST');
        const refreshHeaders = toHeaders(refreshTokenEvent.diagnostic?.['headers']);
        expect(
          refreshHeaders.get('content-type')?.toLowerCase(),
          'Refresh Token Request must be form-urlencoded'
        ).toContain('application/x-www-form-urlencoded');
        expect(refreshHeaders.get('dpop'), 'Refresh Token Request must include DPoP proof').not.toBeNull();
        expect(
          refreshHeaders.get('oauth-client-attestation'),
          'Refresh Token Request must include attestation'
        ).not.toBeNull();
        expect(
          refreshHeaders.get('oauth-client-attestation-pop'),
          'Refresh Token Request must include attestation PoP'
        ).not.toBeNull();

        const originalRefreshTokenHash = requiredDiagnosticString(initialTokenEvent, 'refreshTokenSha256');
        const presentedRefreshTokenHash = requiredDiagnosticString(refreshTokenEvent, 'presentedRefreshTokenSha256');
        expect(presentedRefreshTokenHash, 'Presented Refresh Token must match the one from initial issuance').toBe(
          originalRefreshTokenHash
        );
        expect(
          sha256Base64Url(refreshTokenRequest.grant.refreshToken),
          'Parsed Refresh Token hash must match evidence'
        ).toBe(originalRefreshTokenHash);

        const initialAccessTokenHash = requiredDiagnosticString(initialTokenEvent, 'accessTokenSha256');
        const refreshedAccessTokenHash = requiredDiagnosticString(refreshTokenEvent, 'accessTokenSha256');
        expect(refreshedAccessTokenHash, 'Refreshed Access Token must be distinct from original').not.toBe(
          initialAccessTokenHash
        );
        expect(
          requiredDiagnosticString(refreshTokenEvent, 'refreshTokenSha256'),
          'Refresh Token response must rotate the Refresh Token'
        ).not.toBe(originalRefreshTokenHash);
        expect(
          requiredDiagnosticNumber(refreshTokenEvent, 'accessTokenExpiresIn'),
          'Refreshed Access Token lifetime must match the updated issuer config'
        ).toBe(WP_CREDENTIAL_REISSUANCE_REFRESHED_ACCESS_TOKEN_TTL_SECONDS);

        const { header: initialDpopHeader, payload: initialDpopPayload } = decodeJwt({
          jwt: initialTokenRequest.dpop.jwt,
          headerSchema: zDpopJwtHeader,
          payloadSchema: zDpopJwtPayload
        });
        const { header: refreshDpopHeader, payload: refreshDpopPayload } = decodeJwt({
          jwt: refreshTokenRequest.dpop.jwt,
          headerSchema: zDpopJwtHeader,
          payloadSchema: zDpopJwtPayload
        });
        expect(refreshDpopHeader.typ, 'Refresh DPoP proof typ must be dpop+jwt').toBe('dpop+jwt');
        expect(refreshDpopPayload.htm, 'Refresh DPoP proof must bind POST').toBe('POST');
        expect(refreshDpopPayload.htu, 'Refresh DPoP proof must bind the Token Endpoint URL').toBe(
          htuFromRequestUrl(`${config['credential-issuer'].url}/token`)
        );
        expect(refreshDpopPayload.iat, 'Refresh DPoP proof must carry iat').toBeTypeOf('number');
        expect(
          Math.abs(Date.parse(refreshTokenEvent.timestamp) - refreshDpopPayload.iat * 1000),
          'Refresh DPoP proof iat must be fresh relative to the observed request'
        ).toBeLessThanOrEqual(DPOP_IAT_FRESHNESS_TOLERANCE_SECONDS * 1000);
        expect(refreshDpopPayload.jti, 'Refresh DPoP proof must carry a non-empty jti').not.toHaveLength(0);
        expect(refreshDpopPayload.jti, 'Refresh DPoP proof jti must be fresh').not.toBe(initialDpopPayload.jti);

        const refreshDpopPublicKey = await importJWK(refreshDpopHeader.jwk as JWK, refreshDpopHeader.alg);
        await expect(
          jwtVerify(refreshTokenRequest.dpop.jwt, refreshDpopPublicKey),
          'Refresh DPoP proof signature must verify'
        ).resolves.toBeDefined();
        await expect(
          calculateJwkThumbprint(refreshDpopHeader.jwk as JWK),
          'Refresh DPoP proof must use the same DPoP key as the original Token Request'
        ).resolves.toBe(await calculateJwkThumbprint(initialDpopHeader.jwk as JWK));

        const { payload: initialPopPayload } = decodeJwt({
          jwt: initialTokenRequest.clientAttestation.clientAttestationPopJwt,
          headerSchema: zItWalletClientAttestationPopJwtHeader,
          payloadSchema: zItWalletClientAttestationPopJwtPayload
        });
        const { payload: refreshWalletAttestationPayload } = decodeJwt({
          jwt: refreshTokenRequest.clientAttestation.walletAttestationJwt
        });
        const { payload: refreshPopPayload } = decodeJwt({
          jwt: refreshTokenRequest.clientAttestation.clientAttestationPopJwt,
          headerSchema: zItWalletClientAttestationPopJwtHeader,
          payloadSchema: zItWalletClientAttestationPopJwtPayload
        });
        expect(refreshPopPayload.aud, 'Refresh client-attestation PoP must target the Credential Issuer').toBe(
          config['credential-issuer'].url
        );
        expect(refreshPopPayload.jti, 'Refresh client-attestation PoP must be newly generated').not.toBe(
          initialPopPayload.jti
        );
        const cnfJwk = refreshWalletAttestationPayload.cnf?.jwk;
        expect(cnfJwk, 'Refresh Wallet Attestation must bind a public key').toBeDefined();
        if (!cnfJwk) {
          throw new Error('Refresh Wallet Attestation payload is missing cnf.jwk');
        }
        await expect(
          verifyClientAttestationPopJwt({
            authorizationServer: config['credential-issuer'].url,
            callbacks: { verifyJwt: verifyJwtWithJwk },
            clientAttestationPopJwt: refreshTokenRequest.clientAttestation.clientAttestationPopJwt,
            clientAttestationPublicJwk: cnfJwk
          }),
          'Refresh client-attestation PoP must verify against the Wallet Attestation key'
        ).resolves.toBeDefined();

        const credentialEvents = eventsByName(events, 'issuer.credential.requested');
        const nonceEvents = eventsByName(events, 'issuer.nonce.requested');
        const secondCredentialEvent = credentialEvents[1];
        const secondNonceEvent = nonceEvents[1];
        if (!secondCredentialEvent || !secondNonceEvent) {
          throw new Error('Missing second Credential Request or second Nonce evidence');
        }
        expect(
          secondCredentialEvent.monotonicMs,
          'Second Credential Request must follow the refresh exchange'
        ).toBeGreaterThan(refreshTokenEvent.monotonicMs);
        expect(
          requiredDiagnosticString(secondCredentialEvent, 'accessTokenSha256'),
          'Second Credential Request must use the refreshed Access Token'
        ).toBe(refreshedAccessTokenHash);
        expect(
          Date.parse(secondCredentialEvent.timestamp),
          'Refreshed Access Token must still be valid when the Credential Request is accepted'
        ).toBeLessThan(requiredDiagnosticNumber(refreshTokenEvent, 'accessTokenExp') * 1000);

        const reissuanceWindowEvents = events.filter(
          (event) =>
            event.monotonicMs > updatedStatusListEvent.monotonicMs && event.monotonicMs < secondIssuedEvent.monotonicMs
        );
        expect(
          reissuanceWindowEvents.filter(
            (event) => event.name === 'issuer.par.requested' || event.name === 'issuer.authorization.requested'
          ),
          'Refresh-token re-issuance must not start a second PAR or Authorization request'
        ).toHaveLength(0);

        const secondCredentialRequest = parseCredentialRequestFromEvent(secondCredentialEvent);
        const [proofJwt] = secondCredentialRequest.proofs.jwt;
        if (!proofJwt) {
          throw new Error('Second Credential Request is missing holder-binding proof JWT');
        }
        const credentialDpopJwt = requiredDiagnosticString(secondCredentialEvent, 'dpopProof');
        const { header: credentialDpopHeader, payload: credentialDpopPayload } = decodeJwt({
          jwt: credentialDpopJwt,
          headerSchema: zDpopJwtHeader,
          payloadSchema: zDpopJwtPayload
        });
        expect(credentialDpopPayload.ath, 'Second Credential DPoP ath must match the refreshed Access Token').toBe(
          refreshedAccessTokenHash
        );
        await expect(
          calculateJwkThumbprint(credentialDpopHeader.jwk as JWK),
          'Second Credential Request DPoP key must match the refresh Token Request DPoP key'
        ).resolves.toBe(await calculateJwkThumbprint(refreshDpopHeader.jwk as JWK));

        const { header: proofHeader, payload: proofPayload } = decodeJwt({
          jwt: proofJwt,
          headerSchema: zProofJwtHeaderV1_3,
          payloadSchema: zProofJwtPayload
        });
        const proofPublicKey = await importJWK(proofHeader.jwk as JWK, proofHeader.alg);
        await expect(
          jwtVerify(proofJwt, proofPublicKey),
          'Holder-binding proof JWT must verify'
        ).resolves.toBeDefined();
        const secondNonceHash = requiredDiagnosticString(secondNonceEvent, 'cNonceSha256');
        expect(sha256Base64Url(proofPayload.nonce), 'Holder-binding proof must use the second nonce').toBe(
          secondNonceHash
        );
        expect(secondNonceHash, 'Second nonce must be fresh').not.toBe(
          requiredDiagnosticString(nonceEvents[0], 'cNonceSha256')
        );

        expect(
          requiredDiagnosticString(secondIssuedEvent, 'responseHash'),
          'Replacement credential response hash must be present'
        ).not.toHaveLength(0);
        expect(
          requiredDiagnosticString(secondIssuedEvent, 'responseHash'),
          'Replacement credential response must differ from the initial response'
        ).not.toBe(requiredDiagnosticString(firstIssuedEvent, 'responseHash'));
      },
      wpCredentialReissuanceRefreshAccessTokenScenario.timeouts.vitestTestMs
    );
  });

  describe('WP_Reissuance_ValidAccessToken', () => {
    let outcome: ScenarioOutcome;
    let events: ObservedEvent[];
    let statusListJwt: string;

    beforeAll(async () => {
      const session = await runner.start(wpCredentialReissuanceValidAccessTokenScenario.id);
      try {
        await session.showInstructions();

        const firstIssuedEvent = await session.events.waitFor('issuer.credential.issued', {
          timeoutMs: wpCredentialReissuanceValidAccessTokenScenario.timeouts.protocolStepMs,
          signal: session.abortSignal
        });
        await waitForObservedNominalStatusListCacheExpiry(session.events.all(), session.abortSignal);

        await issuerFaultController.activateIssuerConfig({
          scenarioId: session.correlationId,
          config: {
            batchIssuanceByDeferred: wpCredentialReissuanceValidAccessTokenUpdatedIssuerConfig.batchIssuanceByDeferred,
            accessTokenTtlSeconds: wpCredentialReissuanceValidAccessTokenUpdatedIssuerConfig.accessTokenTtlSeconds,
            refreshTokenTtlSeconds: wpCredentialReissuanceValidAccessTokenUpdatedIssuerConfig.refreshTokenTtlSeconds,
            statusList: {
              bits: wpCredentialReissuanceValidAccessTokenUpdatedIssuerConfig.statusList.bits,
              values: [...wpCredentialReissuanceValidAccessTokenUpdatedIssuerConfig.statusList.values]
            }
          }
        });

        await waitForUpdatedStatusListEvent(
          session.events,
          firstIssuedEvent,
          session.abortSignal,
          wpCredentialReissuanceValidAccessTokenScenario.timeouts.protocolStepMs
        );

        outcome = await session.awaitVerdict();
        events = session.events.all();
        statusListJwt = await fetchStatusListJwt(
          requiredDiagnosticString(nthEvent(events, 'issuer.credential.issued', 0), 'statusListUri')
        );
      } finally {
        await session.stop();
      }
    }, wpCredentialReissuanceValidAccessTokenScenario.timeouts.vitestTestMs);

    test(
      'WP_071: Wallet Instance re-issues the credential with the still-valid associated Access Token.',
      async () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        const firstIssuedEvent = nthEvent(events, 'issuer.credential.issued', 0);
        const secondIssuedEvent = nthEvent(events, 'issuer.credential.issued', 1);
        const updatedStatusListEvent = events.find(isUpdatedStatusListEvent);
        expect(updatedStatusListEvent, 'Updated Status List request evidence must be observed').toBeDefined();
        if (!updatedStatusListEvent) {
          throw new Error('Missing issuer.status_list.requested evidence for the updated Status List');
        }

        expect(
          updatedStatusListEvent.monotonicMs,
          'Status List request must happen after first issuance'
        ).toBeGreaterThan(firstIssuedEvent.monotonicMs);

        const credentialEvents = eventsByName(events, 'issuer.credential.requested');
        const nonceEvents = eventsByName(events, 'issuer.nonce.requested');
        const firstCredentialEvent = credentialEvents[0];
        const secondCredentialEvent = credentialEvents[1];
        const secondNonceEvent = nonceEvents[1];
        if (!firstCredentialEvent || !secondCredentialEvent || !secondNonceEvent) {
          throw new Error('Missing initial/second Credential Request or second Nonce evidence');
        }

        expect(
          updatedStatusListEvent.monotonicMs,
          'Updated Status List request must happen before the second Credential Request'
        ).toBeLessThan(secondCredentialEvent.monotonicMs);
        expect(
          secondIssuedEvent.monotonicMs,
          'Second issuance must follow the second Credential Request'
        ).toBeGreaterThan(secondCredentialEvent.monotonicMs);

        const { payload } = decodeJwt({ jwt: statusListJwt });
        const statusList = payload.status_list as { bits?: unknown; lst?: unknown } | undefined;
        expect(statusList?.bits, 'Status List must use four-bit statuses').toBe(4);
        expect(typeof statusList?.lst, 'Status List must carry a compressed list').toBe('string');
        if (statusList?.bits !== 4 || typeof statusList.lst !== 'string') {
          throw new Error('Status List JWT payload is missing a valid four-bit status_list');
        }
        expect(
          getStatusFromCompressedStatusList(statusList.lst, statusList.bits, WP_CREDENTIAL_REISSUANCE_STATUS_INDEX),
          'Credential index 1 must resolve to UPDATE'
        ).toBe(WP_CREDENTIAL_REISSUANCE_UPDATED_STATUS);

        const tokenEvents = eventsByName(events, 'issuer.token.requested');
        expect(tokenEvents, 'Exactly one successful Token Endpoint exchange must be observed').toHaveLength(1);
        const [tokenEvent] = tokenEvents;
        if (!tokenEvent) {
          throw new Error('Missing original Token exchange evidence');
        }
        expect(tokenEvent.diagnostic?.['grantType'], 'The only Token exchange must use authorization_code').toBe(
          'authorization_code'
        );
        const tokenRequest = parseTokenRequestFromEvent(tokenEvent, config['credential-issuer'].url);
        expect(tokenRequest.grant.grantType, 'Original Token exchange must parse as authorization_code').toBe(
          'authorization_code'
        );

        const reissuanceWindowEvents = events.filter(
          (event) =>
            event.monotonicMs > updatedStatusListEvent.monotonicMs && event.monotonicMs < secondIssuedEvent.monotonicMs
        );
        expect(
          reissuanceWindowEvents.filter((event) => event.name === 'issuer.token.failed'),
          'No Token Endpoint failure may occur during valid-token re-issuance'
        ).toHaveLength(0);
        expect(
          reissuanceWindowEvents.filter(
            (event) =>
              event.name === 'issuer.par.requested' ||
              event.name === 'issuer.authorization.requested' ||
              event.name === 'issuer.token.requested'
          ),
          'Valid-token re-issuance must not start a second PAR, Authorization, or Token exchange'
        ).toHaveLength(0);

        const originalTokenHash = requiredDiagnosticString(tokenEvent, 'accessTokenSha256');
        const originalTokenExp = requiredDiagnosticNumber(tokenEvent, 'accessTokenExp');
        const firstAccessTokenHash = requiredDiagnosticString(firstCredentialEvent, 'accessTokenSha256');
        const secondAccessTokenHash = requiredDiagnosticString(secondCredentialEvent, 'accessTokenSha256');
        expect(firstAccessTokenHash, 'Initial Credential Request must use the issued Access Token').toBe(
          originalTokenHash
        );
        expect(secondAccessTokenHash, 'Second Credential Request must reuse the original Access Token').toBe(
          originalTokenHash
        );
        expect(
          Date.parse(secondCredentialEvent.timestamp),
          'Second Credential Request must arrive before the original Access Token signed expiry'
        ).toBeLessThan(originalTokenExp * 1000);
        expect(
          originalTokenExp * 1000 - Date.parse(tokenEvent.timestamp),
          'Original Access Token lifetime must be long enough for WP_071'
        ).toBeGreaterThanOrEqual(WP_CREDENTIAL_REISSUANCE_VALID_ACCESS_TOKEN_TTL_SECONDS * 1000 - 1_000);

        expect(secondCredentialEvent.diagnostic?.['authorizationScheme']).toBe('DPoP');
        const secondCredentialRequest = parseCredentialRequestFromEvent(secondCredentialEvent);
        const [proofJwt] = secondCredentialRequest.proofs.jwt;
        if (!proofJwt) {
          throw new Error('Second Credential Request is missing holder-binding proof JWT');
        }

        const credentialDpopJwt = requiredDiagnosticString(secondCredentialEvent, 'dpopProof');
        const { header: credentialDpopHeader, payload: credentialDpopPayload } = decodeJwt({
          jwt: credentialDpopJwt,
          headerSchema: zDpopJwtHeader,
          payloadSchema: zDpopJwtPayload
        });
        const { header: proofHeader, payload: proofPayload } = decodeJwt({
          jwt: proofJwt,
          headerSchema: zProofJwtHeaderV1_3,
          payloadSchema: zProofJwtPayload
        });

        const credentialRequestUrl = `${config['credential-issuer'].url}${requiredDiagnosticString(
          secondCredentialEvent,
          'endpoint'
        )}`;
        const dpopPublicKey = await importJWK(credentialDpopHeader.jwk as JWK, credentialDpopHeader.alg);
        await expect(
          jwtVerify(credentialDpopJwt, dpopPublicKey),
          'Second Credential DPoP proof must verify'
        ).resolves.toBeDefined();
        expect(credentialDpopPayload.htm, 'Second Credential DPoP proof must bind POST').toBe('POST');
        expect(credentialDpopPayload.htu, 'Second Credential DPoP proof must bind the Credential Endpoint URL').toBe(
          htuFromRequestUrl(credentialRequestUrl)
        );
        expect(credentialDpopPayload.iat, 'Second Credential DPoP proof must carry iat').toBeTypeOf('number');
        expect(credentialDpopPayload.jti, 'Second Credential DPoP proof must carry jti').not.toHaveLength(0);
        expect(credentialDpopPayload.ath, 'Second Credential DPoP ath must match the reused access token').toBe(
          secondAccessTokenHash
        );

        const { header: tokenDpopHeader } = decodeJwt({
          jwt: tokenRequest.dpop.jwt,
          headerSchema: zDpopJwtHeader,
          payloadSchema: zDpopJwtPayload
        });
        await expect(
          calculateJwkThumbprint(credentialDpopHeader.jwk as JWK),
          'Credential Request DPoP key must match the original Token Request DPoP key'
        ).resolves.toBe(await calculateJwkThumbprint(tokenDpopHeader.jwk as JWK));

        const proofPublicKey = await importJWK(proofHeader.jwk as JWK, proofHeader.alg);
        await expect(
          jwtVerify(proofJwt, proofPublicKey),
          'Holder-binding proof JWT must verify'
        ).resolves.toBeDefined();
        const secondNonceHash = requiredDiagnosticString(secondNonceEvent, 'cNonceSha256');
        expect(sha256Base64Url(proofPayload.nonce), 'Holder-binding proof must use the second nonce').toBe(
          secondNonceHash
        );
        expect(secondNonceHash, 'Second nonce must be fresh').not.toBe(
          requiredDiagnosticString(nonceEvents[0], 'cNonceSha256')
        );

        expect(
          requiredDiagnosticString(secondIssuedEvent, 'responseHash'),
          'Replacement credential response hash must be present'
        ).not.toHaveLength(0);
        expect(
          requiredDiagnosticString(secondIssuedEvent, 'responseHash'),
          'Replacement credential response must differ from the initial response'
        ).not.toBe(requiredDiagnosticString(firstIssuedEvent, 'responseHash'));
      },
      wpCredentialReissuanceValidAccessTokenScenario.timeouts.vitestTestMs
    );
  });

  describe('WP_064 / WP_064a / WP_064b', () => {
    let outcome: ScenarioOutcome;
    let events: ObservedEvent[];

    beforeAll(async () => {
      const session = await runner.start(wpNotificationScenario.id);

      try {
        await session.showInstructions();
        outcome = await session.awaitVerdict();
        events = session.events.all();
      } finally {
        await session.stop();
      }
    }, wpNotificationScenario.timeouts.vitestTestMs);

    test(
      'WP_064: Wallet Instance sends the Notification Request as an HTTP POST to /notification with a JSON media type.',
      () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        const notificationEvent = events.find((event) => event.name === 'issuer.notification.received');
        expect(notificationEvent, 'issuer.notification.received evidence must be observed').toBeDefined();
        if (!notificationEvent) {
          throw new Error('Missing issuer.notification.received evidence');
        }

        expect(notificationEvent.diagnostic?.['endpoint']).toBe('/notification');
        expect(notificationEvent.diagnostic?.['method']).toBe('POST');

        const contentTypeHeader = notificationEvent.diagnostic?.['contentType'];
        const contentType = Array.isArray(contentTypeHeader) ? contentTypeHeader[0] : contentTypeHeader;
        expect(contentType, 'Notification Request must declare a content type').toBeDefined();

        // Normalize away an optional charset parameter instead of requiring an exact string match.
        const mediaType = contentType?.split(';')[0]?.trim().toLowerCase();
        expect(mediaType).toBe('application/json');
      },
      wpNotificationScenario.timeouts.vitestTestMs
    );

    test(
      'WP_064a: Notification Request notification_id matches the Credential Response and event is one of the allowed case-sensitive values.',
      () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        const issuedEvent = events.find((event) => event.name === 'issuer.credential.issued');
        expect(issuedEvent, 'issuer.credential.issued evidence must be observed').toBeDefined();
        const notificationEvent = events.find((event) => event.name === 'issuer.notification.received');
        expect(notificationEvent, 'issuer.notification.received evidence must be observed').toBeDefined();
        if (!issuedEvent || !notificationEvent) {
          throw new Error('Missing issuer.credential.issued or issuer.notification.received evidence');
        }

        const issuedNotificationIdSha256 = requiredDiagnosticString(issuedEvent, 'notificationIdSha256');
        const receivedNotificationIdSha256 = requiredDiagnosticString(notificationEvent, 'notificationIdSha256');
        expect(
          receivedNotificationIdSha256,
          'Notification Request notification_id must match the one issued in the Credential Response'
        ).toBe(issuedNotificationIdSha256);

        expect(
          ['credential_accepted', 'credential_deleted', 'credential_failure'],
          'event must be one of the three case-sensitive enum values'
        ).toContain(notificationEvent.diagnostic?.['event']);
      },
      wpNotificationScenario.timeouts.vitestTestMs
    );

    test(
      'WP_064b: an optional event_description, when present, is generic and user-neutral rather than a privacy-sensitive disclosure.',
      () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        const notificationEvent = events.find((event) => event.name === 'issuer.notification.received');
        expect(notificationEvent, 'issuer.notification.received evidence must be observed').toBeDefined();
        if (!notificationEvent) {
          throw new Error('Missing issuer.notification.received evidence');
        }

        const eventDescriptionPresent = notificationEvent.diagnostic?.['eventDescriptionPresent'];
        if (!eventDescriptionPresent) {
          // event_description is optional: omitting it trivially satisfies this criterion.
          return;
        }

        expect(
          notificationEvent.diagnostic?.['eventDescriptionUserNeutral'],
          `event_description must be generic and user-neutral; reason codes: ${JSON.stringify(
            notificationEvent.diagnostic?.['eventDescriptionReasonCodes']
          )}`
        ).toBe(true);
      },
      wpNotificationScenario.timeouts.vitestTestMs
    );
  });
});
