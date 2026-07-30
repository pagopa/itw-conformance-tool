import { createHash, randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';

import { loadConfig, type ConfigSchemaType } from '@itw-conformance-tool/config';
import { DatabaseClient } from '@itw-conformance-tool/database';
import { createServiceControlClient, type ServiceControlClient } from '@itw-conformance-tool/ipc';
import { compactDecrypt, decodeJwt, decodeProtectedHeader, importJWK, type JWK } from 'jose';
import { afterAll, beforeAll, describe, expect, test } from 'vitest';

import { trimTrailingSlash } from '../../helpers/general.js';
import { decodeEntityConfiguration } from '../../helpers/provider.js';
import {
  assertConformanceOutcome,
  createProtocolObservedScenarioRunner,
  createSqliteScenarioEventBridge,
  presentationScenarioRegistry,
  wp079Scenario,
  wp080Scenario,
  wp081Scenario,
  wp084Scenario,
  wp085Scenario,
  wp086Scenario,
  wp087Scenario,
  wp090Scenario,
  wp091aScenario,
  wp094aScenario,
  wp116Scenario,
  wpRpHappyPostScenario,
  wpRpHappyScenario
} from '../../index.js';
import { httpsRequest } from '../../utils/request.js';

import type {
  ObservedEvent,
  ProtocolObservedScenarioDefinition,
  ScenarioOutcome,
  ScenarioRunner
} from '../../index.js';

// Key Binding JWT signature algorithms the Relying Party advertises for the
// dc+sd-jwt format (client_metadata.vp_formats_supported['dc+sd-jwt']
// ['kb-jwt_alg_values']).
const SUPPORTED_KB_JWT_ALGS = ['ES256', 'ES384', 'ES512'];

interface SdJwtPresentationParts {
  disclosures: string[];
  issuerJwt: string;
  kbJwt: string;
}

// An SD-JWT VC presentation is serialized as
// `<issuer-signed JWT>~<disclosure 1>~...~<disclosure N>~<KB-JWT>`; the Key
// Binding JWT is the final `~`-separated segment.
function splitSdJwtPresentation(token: string): SdJwtPresentationParts {
  const segments = token.split('~');
  if (segments.length < 2) {
    throw new Error('SD-JWT presentation must contain at least an issuer JWT and a Key Binding JWT');
  }

  return {
    issuerJwt: segments[0],
    kbJwt: segments[segments.length - 1],
    disclosures: segments.slice(1, -1)
  };
}

// A vp_token entry is a single SD-JWT presentation string or an array of them.
function normalizeVpTokenEntry(value: unknown): string[] {
  if (typeof value === 'string') return [value];
  if (Array.isArray(value) && value.every((entry) => typeof entry === 'string')) return value as string[];
  throw new Error('vp_token entry must be a string or an array of strings');
}

// The Relying Party loads its encryption key pair from `<data_dir>/rp/jwks.json`
// at startup (apps/itw-relying-party/src/plugins/jwk.ts) and decrypts the
// Authorization Response JWE with its private ECDH-ES key. WP_092 reads the key
// from that same file, rather than from the SQLite event store, so the test
// decrypts with the exact key material the RP itself uses.
const RP_JWKS_FILE = 'rp/jwks.json';

async function loadRpEncryptionPrivateJwk(dataDir: string): Promise<JWK> {
  const filePath = path.join(dataDir, RP_JWKS_FILE);
  const parsed = JSON.parse(await readFile(filePath, 'utf8')) as { keys?: unknown };

  if (!Array.isArray(parsed.keys)) {
    throw new Error(`${filePath} must contain a JWKS with a keys array`);
  }

  const encryptionJwk = parsed.keys.find(
    (key): key is JWK =>
      typeof key === 'object' &&
      key !== null &&
      (key as JWK).alg === 'ECDH-ES' &&
      (key as { use?: unknown }).use === 'enc'
  );

  if (!encryptionJwk) {
    throw new Error(`${filePath} must contain an ECDH-ES 'enc' JWK`);
  }
  if (typeof encryptionJwk.d !== 'string') {
    throw new Error(`${filePath} encryption JWK is missing its private component`);
  }

  return encryptionJwk;
}

// The decrypted JARM payload is either the Authorization Response JSON
// (encryption-only) or a signed JWT wrapping it (signed + encrypted); either
// way it carries the OpenID4VP response parameters (vp_token, state, ...).
function decodeDecryptedAuthorizationResponse(plaintext: string): Record<string, unknown> {
  const trimmed = plaintext.trim();
  const payload = trimmed.startsWith('{') ? (JSON.parse(trimmed) as unknown) : decodeJwt(trimmed);
  if (typeof payload !== 'object' || payload === null) {
    throw new Error('Decrypted Authorization Response is not a JSON object');
  }
  return payload as Record<string, unknown>;
}

// Set by the CLI's local control relay (`itwct test presentation`/`itwct test`)
// before spawning this Vitest process; see `apps/cli/src/commands/runTests.ts`.
const SERVICE_CONTROL_ENDPOINT_ENV_VAR = 'ITWCT_SERVICE_CONTROL_ENDPOINT';

/**
 * Optional comma-separated allow-list of scenario IDs to run; unset runs them
 * all.
 *
 * Every scenario here is interactive: it shows one engagement and then waits, up
 * to `testerActionMs`, for a wallet to act on it. An automated run therefore
 * needs a wallet driver that reacts to each engagement in turn and implements
 * the behaviour the scenario is about — a negative scenario only concludes
 * quickly when the wallet actually performs the check under test. Selecting a
 * subset keeps such a run bounded instead of paying the tester timeout for every
 * scenario the driver cannot satisfy.
 */
const SCENARIO_IDS_ENV_VAR = 'ITWCT_PRESENTATION_SCENARIO_IDS';

const selectedScenarioIds = (process.env[SCENARIO_IDS_ENV_VAR] ?? '')
  .split(',')
  .map((id) => id.trim())
  .filter((id) => id.length > 0);

function isSelected(definition: ProtocolObservedScenarioDefinition): boolean {
  return selectedScenarioIds.length === 0 || selectedScenarioIds.includes(definition.id);
}

/**
 * `wallet_metadata` member names the specification requires the Wallet Instance
 * to send on a `request_uri_method=post` retrieval (WP_083a).
 */
const REQUIRED_WALLET_METADATA_MEMBERS = [
  'vp_formats_supported',
  'client_id_prefixes_supported',
  'authorization_endpoint',
  'response_types_supported'
];

/**
 * WP_083b: `wallet_metadata` must carry no user-identifiable or device-specific
 * data. Telling personal from generic data is not decidable in general — the
 * Test Coverage Gap analysis classifies this case as only partially automatable
 * — so this is a conservative deny-list over the JSON member names plus a scan
 * of the string values for e-mail addresses and Italian fiscal codes. It catches
 * the unambiguous violations without claiming completeness.
 */
const PERSONAL_DATA_MEMBER_FRAGMENTS = [
  'given_name',
  'family_name',
  'birth',
  'email',
  'phone',
  'msisdn',
  'tax_id',
  'fiscal_code',
  'codice_fiscale',
  'ssn',
  'imei',
  'imsi',
  'serial_number',
  'advertising',
  'device_id',
  'device_name',
  'installation_id',
  'user_id',
  'username'
];

const EMAIL_ADDRESS_PATTERN = /[\w.+-]+@[\w-]+\.[\w.-]+/;
const ITALIAN_FISCAL_CODE_PATTERN = /\b[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]\b/;

interface JsonEntries {
  memberNames: string[];
  stringValues: string[];
}

/** Flattens a decoded JSON value into its member names and string values. */
function collectJsonEntries(
  value: unknown,
  collected: JsonEntries = { memberNames: [], stringValues: [] }
): JsonEntries {
  if (typeof value === 'string') {
    collected.stringValues.push(value);
    return collected;
  }

  if (Array.isArray(value)) {
    for (const entry of value) collectJsonEntries(entry, collected);
    return collected;
  }

  if (typeof value === 'object' && value !== null) {
    for (const [memberName, memberValue] of Object.entries(value)) {
      collected.memberNames.push(memberName);
      collectJsonEntries(memberValue, collected);
    }
  }

  return collected;
}

interface PresentationRun {
  events: ObservedEvent[];
  outcome: ScenarioOutcome;
}

describe('Test Cases for Presentation Phase', () => {
  let runner: ScenarioRunner;
  let db: DatabaseClient;
  let dataDir: string;
  let config: ConfigSchemaType;
  let rpFaultController: ServiceControlClient;

  beforeAll(() => {
    config = loadConfig();
    dataDir = config.global.data_dir;
    db = new DatabaseClient(dataDir);

    const controlEndpoint = process.env[SERVICE_CONTROL_ENDPOINT_ENV_VAR];
    if (!controlEndpoint) {
      throw new Error(
        `Missing ${SERVICE_CONTROL_ENDPOINT_ENV_VAR}: run this suite via the itwct CLI (e.g. itwct test presentation), which starts the local service control relay required by the negative presentation scenarios.`
      );
    }
    rpFaultController = createServiceControlClient({ endpoint: controlEndpoint });

    const federation = config['trust-anchor'].url;
    const relyingParty = config['relying-party'].url;
    runner = createProtocolObservedScenarioRunner({
      endpoints: { federation, relyingParty },
      eventBridgeFactory: createSqliteScenarioEventBridge({ db }),
      registry: presentationScenarioRegistry,
      rpFaultController,
      rpFaultSpecVersion: '1.3'
    });
  });

  afterAll(async () => {
    await runner.close();
    await rpFaultController.close();
    db.close();
  });

  /**
   * Runs one interactive scenario to its verdict. `session.stop()` — which
   * deactivates the scenario's Relying Party fault — runs even when the verdict
   * or a later assertion fails, so no scenario leaks fault state onto the next.
   */
  async function runPresentationScenario(definition: ProtocolObservedScenarioDefinition): Promise<PresentationRun> {
    const session = await runner.start(definition.id);

    try {
      await session.showInstructions();
      const outcome = await session.awaitVerdict();

      return { outcome, events: session.events.all() };
    } finally {
      await session.stop();
    }
  }

  function findEvent(events: ObservedEvent[], name: string): ObservedEvent | undefined {
    return events.find((candidate) => candidate.name === name);
  }

  /** Asserts the Relying Party served the artifact this scenario's fault mutated. */
  function expectFaultApplied(
    events: ObservedEvent[],
    faultProfileType: string,
    diagnostics: Record<string, unknown> = {}
  ): void {
    const faultApplied = findEvent(events, 'rp.fault.applied');
    expect(faultApplied, `The ${faultProfileType} fault must have been applied by the Relying Party`).toBeDefined();
    expect(faultApplied?.diagnostic?.['faultProfileType']).toBe(faultProfileType);
    expect(faultApplied?.diagnostic?.['outcome']).toBe('applied');
    for (const [key, value] of Object.entries(diagnostics)) {
      expect(faultApplied?.diagnostic?.[key], `The applied fault evidence must report ${key}`).toBe(value);
    }
  }

  /**
   * Fetches the Relying Party Entity Configuration the wallet resolves.
   *
   * Local services use ephemeral, self-signed certificates (see
   * @itw-conformance-tool/crypto's createHttpsOptions), so a plain global
   * `fetch()` fails TLS verification. Use `httpsRequest` with
   * `rejectUnauthorized: false`, matching the convention used for these hosts.
   */
  async function fetchRelyingPartyEntityConfiguration(): Promise<ReturnType<typeof decodeEntityConfiguration>> {
    const discoveryUrl = new URL('/.well-known/openid-federation', config['relying-party'].url);
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
        `Unable to fetch Relying Party entity configuration (${response.statusCode ?? 'unknown'}): ${response.body}`
      );
    }

    return decodeEntityConfiguration(response.body);
  }

  /** The signing/encryption keys the Relying Party publishes for verifiers. */
  function verifierJwks(claims: ReturnType<typeof decodeEntityConfiguration>): { kid?: string }[] {
    const verifier = claims.metadata?.openid_credential_verifier as
      { jwks?: { keys?: { kid?: string }[] } } | undefined;
    return verifier?.jwks?.keys ?? [];
  }

  /** Asserts the wallet never sent an Authorization Response carrying a vp_token. */
  function expectNoPresentation(events: ObservedEvent[], reason: string): void {
    const presentation = events.find(
      (event) => event.name === 'rp.presentation_response.received' && event.diagnostic?.['outcome'] === 'response'
    );
    expect(presentation, reason).toBeUndefined();
    expect(
      findEvent(events, 'vp_token.validation.succeeded'),
      'No presentation may be verified by the Relying Party in a negative scenario'
    ).toBeUndefined();
  }

  // A single happy-path remote presentation run exercises every
  // RP/Trust-Anchor-observable endpoint call, so one flow satisfies many Wallet
  // Solution Test Matrix cases at once. Some cases are satisfied by the protocol
  // verdict alone (the required event was observed); the WP_082/091/092/093x/094
  // cases additionally analyze the request/response payloads the RP forwards into
  // the event diagnostics.
  //
  // Conflicting cases are resolved by choosing one variant: WP_076 (deep-link /
  // same-device) over WP_077 (QR / cross-device) so the WP_094 redirect is
  // observable, and WP_082 (GET) over WP_083 (POST) — the RP advertises no
  // request_uri_method, so the wallet fetches the Request Object over GET. The
  // negative cases (WP_081, WP_085, WP_086, WP_087, WP_090, WP_091a, WP_094a) and
  // the UI-only cases (WP_088, WP_089, WP_089a, WP_089b) require dedicated
  // unhappy-path scenarios and are intentionally excluded.
  describe.skipIf(!isSelected(wpRpHappyScenario))('Happy path — full remote presentation flow', () => {
    let outcome: ScenarioOutcome;
    let events: ObservedEvent[];

    beforeAll(async () => {
      const session = await runner.start(wpRpHappyScenario.id);

      try {
        await session.showInstructions();
        outcome = await session.awaitVerdict();
        events = session.events.all();
      } finally {
        await session.stop();
      }
    }, wpRpHappyScenario.timeouts.vitestTestMs);

    function requireEvent(name: string): ObservedEvent {
      const event = events.find((candidate) => candidate.name === name);
      if (!event) {
        throw new Error(`Missing ${name} evidence required for presentation analysis`);
      }
      return event;
    }

    function requiredDiagnosticString(event: ObservedEvent, key: string): string {
      const value = event.diagnostic?.[key];
      if (typeof value !== 'string' || value.length === 0) {
        throw new Error(`${event.name} evidence is missing the ${key} diagnostic`);
      }
      return value;
    }

    // Every SD-JWT presentation carried by the vp_token, flattened across
    // credential ids.
    function vpTokenPresentations(): string[] {
      const succeeded = requireEvent('vp_token.validation.succeeded');
      const vpToken = succeeded.diagnostic?.['vpToken'];
      if (typeof vpToken !== 'object' || vpToken === null) {
        throw new Error('vp_token.validation.succeeded evidence is missing the vpToken diagnostic');
      }

      return Object.values(vpToken as Record<string, unknown>).flatMap(normalizeVpTokenEntry);
    }

    // Cases whose expected effect is fully covered by the protocol verdict: the
    // required event (federation/metadata fetch, redirect, etc.) was observed.
    const presenceOnlyCases: [id: string, description: string][] = [
      ['WP_076', 'Wallet Instance obtains the Remote Presentation URL from a deep link'],
      ['WP_078', 'Wallet Instance fetches the Relying Party OpenID Federation endpoint']
    ];

    test.each(presenceOnlyCases)('[%s]: %s', () => {
      assertConformanceOutcome(outcome, { expected: 'PASS' });
    });

    test('[WP_082]: Wallet Instance retrieves the Request Object via HTTP GET to the request_uri endpoint', () => {
      assertConformanceOutcome(outcome, { expected: 'PASS' });

      const requestObjectEvent = requireEvent('rp.request_object.requested');
      expect(requestObjectEvent.diagnostic?.['method'], 'Request Object should be fetched via GET').toBe('GET');
      expect(
        requestObjectEvent.diagnostic?.['endpoint'],
        'Request Object should be fetched from the request_uri endpoint'
      ).toBe('/auth/request/:state');
    });

    test('[WP_091]: Wallet Instance sends the Authorization Response via HTTP POST to the response_uri endpoint', () => {
      assertConformanceOutcome(outcome, { expected: 'PASS' });

      const responseEvent = requireEvent('rp.presentation_response.received');
      expect(responseEvent.diagnostic?.['method'], 'Authorization Response should be sent via POST').toBe('POST');
      expect(responseEvent.diagnostic?.['endpoint'], 'Authorization Response should target the response_uri').toBe(
        '/auth/response'
      );
      expect(
        requiredDiagnosticString(responseEvent, 'response'),
        'Authorization Response should carry a non-empty response payload'
      ).not.toHaveLength(0);
    });

    test('[WP_092]: Wallet Instance encrypts the Authorization Response with the Relying Party key', async () => {
      assertConformanceOutcome(outcome, { expected: 'PASS' });

      const responseEvent = requireEvent('rp.presentation_response.received');
      const rawResponse = requiredDiagnosticString(responseEvent, 'response');

      // The Authorization Response is a compact JWE addressed to the RP.
      expect(rawResponse.split('.'), 'Authorization Response should be a compact JWE (5 segments)').toHaveLength(5);

      const header = decodeProtectedHeader(rawResponse);
      expect(header.alg, 'JWE should declare a key-management alg').toBeTypeOf('string');
      expect(header.enc, 'JWE should declare a content-encryption enc').toBeTypeOf('string');

      // Decrypt with the RP's own encryption private key, loaded from the same
      // `rp/jwks.json` the RP reads at startup and imported the same way the RP
      // imports it (ECDH-ES). A successful decryption proves the wallet encrypted
      // the Authorization Response to the Relying Party's advertised key.
      const encryptionJwk = await loadRpEncryptionPrivateJwk(dataDir);
      expect(header.kid, 'JWE should target the RP encryption key').toBe(encryptionJwk.kid);
      const privateKey = await importJWK(encryptionJwk, 'ECDH-ES');

      const decrypted = await compactDecrypt(rawResponse, privateKey);
      const plaintext = new TextDecoder().decode(decrypted.plaintext);

      // The decrypted payload is the OpenID4VP Authorization Response carrying the
      // vp_token — confirming the ciphertext is the actual response, not just a
      // well-formed but unrelated JWE.
      const payload = decodeDecryptedAuthorizationResponse(plaintext);
      expect(payload.vp_token, 'decrypted Authorization Response should carry a vp_token').toBeDefined();
    });

    test('[WP_093]: Wallet Instance builds the vp_token with the Request Object state and one entry per credential', () => {
      assertConformanceOutcome(outcome, { expected: 'PASS' });

      const succeeded = requireEvent('vp_token.validation.succeeded');

      const state = succeeded.diagnostic?.['state'];
      const requestObjectState = succeeded.diagnostic?.['requestObjectState'];
      expect(state, 'Authorization Response should carry a state').toBeTypeOf('string');
      expect(state, 'Authorization Response state should echo the Request Object state').toBe(requestObjectState);

      const requested = succeeded.diagnostic?.['requestedCredentialIds'];
      const present = succeeded.diagnostic?.['vpTokenCredentialIds'];
      expect(Array.isArray(requested), 'requestedCredentialIds should be an array').toBe(true);
      expect(Array.isArray(present), 'vpTokenCredentialIds should be an array').toBe(true);
      expect((requested as string[]).length, 'at least one credential should be requested').toBeGreaterThan(0);
      expect(
        [...(present as string[])].sort(),
        'vp_token should contain exactly one entry per requested credential'
      ).toEqual([...(requested as string[])].sort());
    });

    test('[WP_093a]: Wallet Instance includes at least one SD-JWT disclosure in the vp_token', () => {
      assertConformanceOutcome(outcome, { expected: 'PASS' });

      const presentations = vpTokenPresentations();
      expect(presentations.length, 'vp_token should contain at least one presentation').toBeGreaterThan(0);

      for (const presentation of presentations) {
        const { disclosures } = splitSdJwtPresentation(presentation);
        expect(disclosures.length, 'each SD-JWT presentation should include at least one disclosure').toBeGreaterThan(
          0
        );
      }
    });

    test('[WP_093b]: Wallet Instance appends a Key Binding JWT to every SD-JWT presentation', () => {
      assertConformanceOutcome(outcome, { expected: 'PASS' });

      for (const presentation of vpTokenPresentations()) {
        const { kbJwt } = splitSdJwtPresentation(presentation);
        expect(kbJwt.split('.'), 'each SD-JWT presentation should end with a Key Binding JWT').toHaveLength(3);
        expect(() => decodeProtectedHeader(kbJwt), 'Key Binding JWT should decode as a JWS').not.toThrow();
      }
    });

    test('[WP_093c]: Wallet Instance uses the required Key Binding JWT header and payload format', () => {
      assertConformanceOutcome(outcome, { expected: 'PASS' });

      const succeeded = requireEvent('vp_token.validation.succeeded');
      const expectedAud = succeeded.diagnostic?.['clientId'];
      const expectedNonce = succeeded.diagnostic?.['nonce'];

      for (const presentation of vpTokenPresentations()) {
        const { issuerJwt, disclosures, kbJwt } = splitSdJwtPresentation(presentation);
        const header = decodeProtectedHeader(kbJwt);
        const payload = decodeJwt(kbJwt);

        expect(header.typ, 'KB-JWT typ should be kb+jwt').toBe('kb+jwt');
        expect(SUPPORTED_KB_JWT_ALGS, 'KB-JWT alg should be a supported signature algorithm').toContain(header.alg);

        expect(payload.iat, 'KB-JWT should carry a numeric iat').toBeTypeOf('number');
        expect(payload.aud, 'KB-JWT aud should match the client_id').toBe(expectedAud);
        expect(payload.nonce, 'KB-JWT nonce should match the Request Object nonce').toBe(expectedNonce);

        const sdHash = payload.sd_hash;
        expect(sdHash, 'KB-JWT should carry a non-empty sd_hash').toBeTypeOf('string');

        // sd_hash binds the KB-JWT to the issuer JWT + disclosures: the SHA-256 of
        // the presentation up to and including the last `~` before the KB-JWT.
        const sdJwtWithoutKb = `${[issuerJwt, ...disclosures].join('~')}~`;
        const expectedSdHash = createHash('sha256').update(sdJwtWithoutKb).digest('base64url');
        expect(sdHash, 'KB-JWT sd_hash should match the SHA-256 of the SD-JWT presentation').toBe(expectedSdHash);
      }
    });

    test('[WP_094]: Wallet Instance follows the redirect_uri returned by the Relying Party', () => {
      assertConformanceOutcome(outcome, { expected: 'PASS' });

      const redirectEvent = requireEvent('rp.redirect.followed');
      expect(redirectEvent.diagnostic?.['method'], 'redirect_uri should be followed via GET').toBe('GET');
      expect(redirectEvent.diagnostic?.['endpoint'], 'redirect should land on the RP callback endpoint').toBe(
        '/callback'
      );

      // The followed URI must be the attested `redirect_uris` entry with only
      // query parameters added, otherwise a wallet comparing it against the
      // Entity Configuration could not have accepted it (WP_094a).
      const followed = new URL(requiredDiagnosticString(redirectEvent, 'redirectUri'));
      expect(
        `${followed.origin}${followed.pathname}`,
        'the redirect_uri path must match the attested callback endpoint exactly'
      ).toBe(`${trimTrailingSlash(config['relying-party'].url)}/callback`);
      expect(followed.searchParams.get('state'), 'the session is identified in the query string').toBeTruthy();
      expect(
        followed.searchParams.get('response_code'),
        'the response_code binds the redirect to the session'
      ).toBeTruthy();
    });
  });

  // The cases the same-device/GET flow above cannot cover in the same run,
  // because each pair is mutually exclusive: the engagement is a QR payload for a
  // cross-device flow (WP_077 instead of WP_076) and advertises
  // request_uri_method=post, so the Request Object is retrieved with a POST
  // carrying wallet_metadata and wallet_nonce (WP_083 and its WP_083a/b/c
  // checks) instead of a GET (WP_082).
  describe.skipIf(!isSelected(wpRpHappyPostScenario))(
    'Happy path — Request Object retrieved with a POST (cross-device)',
    () => {
      let run: PresentationRun;

      beforeAll(async () => {
        run = await runPresentationScenario(wpRpHappyPostScenario);
      }, wpRpHappyPostScenario.timeouts.vitestTestMs);

      function requestObjectEvent(): ObservedEvent {
        const event = findEvent(run.events, 'rp.request_object.requested');
        if (!event) {
          throw new Error('Missing rp.request_object.requested evidence required for the POST retrieval analysis');
        }
        return event;
      }

      function walletMetadata(): Record<string, unknown> {
        const metadata = requestObjectEvent().diagnostic?.['walletMetadata'];
        if (typeof metadata !== 'object' || metadata === null || Array.isArray(metadata)) {
          throw new Error('rp.request_object.requested evidence is missing a wallet_metadata JSON object');
        }
        return metadata as Record<string, unknown>;
      }

      test('[WP_077]: Wallet Instance obtains the Remote Presentation URL from a QR code', () => {
        assertConformanceOutcome(run.outcome, { expected: 'PASS' });
      });

      test('[WP_083]: Wallet Instance retrieves the Request Object via HTTP POST with wallet_metadata and wallet_nonce', () => {
        assertConformanceOutcome(run.outcome, { expected: 'PASS' });

        const event = requestObjectEvent();
        expect(event.diagnostic?.['method'], 'Request Object should be fetched via POST').toBe('POST');
        expect(event.diagnostic?.['endpoint'], 'Request Object should be fetched from the request_uri endpoint').toBe(
          '/auth/request/:state'
        );
        expect(
          String(event.diagnostic?.['contentType'] ?? ''),
          'POST body should be sent as application/x-www-form-urlencoded'
        ).toContain('application/x-www-form-urlencoded');
        expect(
          event.diagnostic?.['walletMetadataWellFormed'],
          'wallet_metadata should be present and parse as JSON'
        ).toBe(true);
        expect(event.diagnostic?.['walletNonce'], 'wallet_nonce should be present in the POST body').toBeTypeOf(
          'string'
        );
      });

      test('[WP_083a]: Wallet Instance formats wallet_metadata as JSON per the specification', () => {
        assertConformanceOutcome(run.outcome, { expected: 'PASS' });

        const metadata = walletMetadata();
        for (const member of REQUIRED_WALLET_METADATA_MEMBERS) {
          expect(Object.keys(metadata), `wallet_metadata should declare ${member}`).toContain(member);
        }
      });

      test('[WP_083b]: wallet_metadata contains no user-identifiable or device-specific data', () => {
        assertConformanceOutcome(run.outcome, { expected: 'PASS' });

        const { memberNames, stringValues } = collectJsonEntries(walletMetadata());

        const personalMembers = memberNames.filter((memberName) =>
          PERSONAL_DATA_MEMBER_FRAGMENTS.some((fragment) => memberName.toLowerCase().includes(fragment))
        );
        expect(
          personalMembers,
          'wallet_metadata should not declare user-identifiable or device-specific members'
        ).toEqual([]);

        const personalValues = stringValues.filter(
          (value) => EMAIL_ADDRESS_PATTERN.test(value) || ITALIAN_FISCAL_CODE_PATTERN.test(value)
        );
        expect(personalValues, 'wallet_metadata values should not contain e-mail addresses or fiscal codes').toEqual(
          []
        );
      });

      test('[WP_083c]: Wallet Instance sends a freshly generated wallet_nonce', () => {
        assertConformanceOutcome(run.outcome, { expected: 'PASS' });

        const event = requestObjectEvent();
        const walletNonce = event.diagnostic?.['walletNonce'];
        expect(walletNonce, 'wallet_nonce should be a non-empty string').toBeTypeOf('string');

        // A single flow cannot prove the nonce is fresh across runs; what it can
        // prove is that the wallet generated an unpredictable value of its own
        // rather than echoing a value the Relying Party gave it.
        const nonce = String(walletNonce);
        expect(nonce.length, 'wallet_nonce should carry enough entropy to prevent replay').toBeGreaterThanOrEqual(16);

        const verified = findEvent(run.events, 'vp_token.validation.succeeded');
        expect(nonce, 'wallet_nonce must not reuse the Relying Party nonce').not.toBe(verified?.diagnostic?.['nonce']);
        expect(nonce, 'wallet_nonce must not reuse the Request Object state').not.toBe(
          verified?.diagnostic?.['requestObjectState']
        );
        expect(event.diagnostic?.['walletNonceEchoed'], 'the Relying Party should echo the wallet_nonce back').toBe(
          true
        );
      });
    }
  );

  describe.skipIf(!isSelected(wp079Scenario))(
    'Negative path — Trust Chain that does not reach the Trust Anchor',
    () => {
      let run: PresentationRun;

      beforeAll(async () => {
        run = await runPresentationScenario(wp079Scenario);
      }, wp079Scenario.timeouts.vitestTestMs);

      test(
        '[WP_079]: Wallet Instance validates the Relying Party Trust Chain and stops when it does not reach the Trust Anchor',
        () => {
          assertConformanceOutcome(run.outcome, { expected: 'PASS' });
          expectFaultApplied(run.events, 'invalid-trust-anchor');

          expect(
            findEvent(run.events, 'federation.fetch.requested'),
            'Wallet must not resolve a subordinate statement from a Trust Anchor the Relying Party does not name'
          ).toBeUndefined();
          expect(
            findEvent(run.events, 'rp.request_object.requested'),
            'Wallet must not retrieve the Request Object after failing to build the Trust Chain'
          ).toBeUndefined();
        },
        wp079Scenario.timeouts.vitestTestMs
      );
    }
  );

  describe.skipIf(!isSelected(wp080Scenario))('Negative path — Trust Mark that cannot be verified', () => {
    let run: PresentationRun;

    beforeAll(async () => {
      run = await runPresentationScenario(wp080Scenario);
    }, wp080Scenario.timeouts.vitestTestMs);

    test(
      '[WP_080]: Wallet Instance evaluates the Relying Party Trust Marks and stops when one cannot be validated',
      () => {
        assertConformanceOutcome(run.outcome, { expected: 'PASS' });
        expectFaultApplied(run.events, 'invalid-trust-mark');

        expect(
          findEvent(run.events, 'rp.request_object.requested'),
          'Wallet must not retrieve the Request Object after failing to validate the Trust Mark'
        ).toBeUndefined();
      },
      wp080Scenario.timeouts.vitestTestMs
    );
  });

  describe.skipIf(!isSelected(wp081Scenario))(
    'Negative path — request_uri absent from the Relying Party metadata',
    () => {
      let run: PresentationRun;

      beforeAll(async () => {
        run = await runPresentationScenario(wp081Scenario);
      }, wp081Scenario.timeouts.vitestTestMs);

      test(
        '[WP_081]: Wallet Instance only retrieves a request_uri attested in the Relying Party metadata',
        () => {
          assertConformanceOutcome(run.outcome, { expected: 'PASS' });
          expectFaultApplied(run.events, 'unattested-request-uri');

          expect(
            findEvent(run.events, 'rp.request_object.requested'),
            'Wallet must not request a request_uri that the Relying Party metadata does not attest'
          ).toBeUndefined();
        },
        wp081Scenario.timeouts.vitestTestMs
      );
    }
  );

  describe.skipIf(!isSelected(wp087Scenario))(
    'Negative path — Relying Party not authorized to request presentations',
    () => {
      let run: PresentationRun;

      beforeAll(async () => {
        run = await runPresentationScenario(wp087Scenario);
      }, wp087Scenario.timeouts.vitestTestMs);

      test(
        '[WP_087]: Wallet Instance authorizes a presentation only when the federation attests the Relying Party may request it',
        () => {
          assertConformanceOutcome(run.outcome, { expected: 'PASS' });
          expectFaultApplied(run.events, 'missing-presentation-trust-mark');

          expect(
            findEvent(run.events, 'rp.request_object.requested'),
            'Wallet must not retrieve the Request Object of a Relying Party the federation does not authorize'
          ).toBeUndefined();
        },
        wp087Scenario.timeouts.vitestTestMs
      );
    }
  );

  // WP_084 is a happy path, not a negative one: the wallet is expected to
  // complete the presentation. What makes the case conclusive is that the
  // Relying Party removed every key source except the federation metadata, so a
  // completed flow can only mean the wallet resolved the key from there.
  describe.skipIf(!isSelected(wp084Scenario))(
    'Happy path — Relying Party key published only in the federation metadata',
    () => {
      let run: PresentationRun;

      beforeAll(async () => {
        run = await runPresentationScenario(wp084Scenario);
      }, wp084Scenario.timeouts.vitestTestMs);

      test(
        '[WP_084]: Wallet Instance resolves the Relying Party public key from metadata.openid_credential_verifier.jwks using the Request Object kid',
        async () => {
          assertConformanceOutcome(run.outcome, { expected: 'PASS' });

          // The served Request Object really did carry no certificate chain,
          // and the kid the wallet had to resolve is recorded alongside it.
          expectFaultApplied(run.events, 'request-object-federation-key', {
            hasX5c: false,
            keyResolution: 'federation'
          });

          const faultApplied = findEvent(run.events, 'rp.fault.applied');
          const signingKeyId = faultApplied?.diagnostic?.['signingKeyId'];
          expect(
            typeof signingKeyId === 'string' && signingKeyId.length > 0,
            'The Request Object must keep a kid: with no x5c it is the only handle on the signing key'
          ).toBe(true);

          expect(
            faultApplied?.diagnostic?.['clientId'],
            'The client_id must carry the openid_federation prefix so the wallet resolves the key through the Trust Chain'
          ).toMatch(/^openid_federation:/);

          // The kid must actually resolve in the Entity Configuration the wallet
          // fetched, otherwise the scenario would be unsatisfiable rather than
          // conclusive.
          const entityConfiguration = await fetchRelyingPartyEntityConfiguration();
          expect(
            verifierJwks(entityConfiguration).map((key) => key.kid),
            'The Request Object signing key must be published in metadata.openid_credential_verifier.jwks'
          ).toContain(signingKeyId);

          // The presentation completed, so the wallet verified a Request Object
          // it could only have verified with that key.
          expect(
            findEvent(run.events, 'vp_token.validation.succeeded'),
            'The Relying Party must have verified a presentation for the federation-signed Request Object'
          ).toBeDefined();
        },
        wp084Scenario.timeouts.vitestTestMs
      );
    }
  );

  describe.skipIf(!isSelected(wp116Scenario))('Happy path — erasure endpoint discovery and request', () => {
    let run: PresentationRun;
    let erasureEndpoint: string | undefined;

    beforeAll(async () => {
      run = await runPresentationScenario(wp116Scenario);
    }, wp116Scenario.timeouts.vitestTestMs);

    function requireEvent(name: string): ObservedEvent {
      const event = findEvent(run.events, name);
      if (!event) {
        throw new Error(`Missing ${name} evidence required for erasure analysis`);
      }
      return event;
    }

    function expectEventOrder(first: string, second: string): void {
      const firstIndex = run.events.findIndex((event) => event.name === first);
      const secondIndex = run.events.findIndex((event) => event.name === second);

      expect(firstIndex, `${first} must be present`).toBeGreaterThanOrEqual(0);
      expect(secondIndex, `${second} must be present`).toBeGreaterThanOrEqual(0);
      expect(firstIndex, `${first} must be observed before ${second}`).toBeLessThan(secondIndex);
    }

    async function verifiedErasureEndpoint(): Promise<string> {
      if (erasureEndpoint) return erasureEndpoint;

      const entityConfiguration = await fetchRelyingPartyEntityConfiguration();
      const verifier = entityConfiguration.metadata?.openid_credential_verifier as
        { erasure_endpoint?: unknown } | undefined;
      const endpoint = verifier?.erasure_endpoint;

      expect(endpoint, 'metadata.openid_credential_verifier.erasure_endpoint must be present').toBeTypeOf('string');

      const parsed = new URL(String(endpoint));
      expect(parsed.protocol, 'erasure_endpoint must use HTTPS').toBe('https:');
      expect(String(endpoint), 'erasure_endpoint must point at the Relying Party /erasure route').toBe(
        `${trimTrailingSlash(config['relying-party'].url)}/erasure`
      );

      erasureEndpoint = String(endpoint);
      return erasureEndpoint;
    }

    test(
      '[WP_116]: Wallet Instance discovers an HTTPS erasure_endpoint from Relying Party metadata',
      async () => {
        assertConformanceOutcome(run.outcome, { expected: 'PASS' });

        expectEventOrder('rp.metadata.requested', 'federation.anchor.requested');
        expectEventOrder('federation.anchor.requested', 'federation.fetch.requested');
        expectEventOrder('federation.fetch.requested', 'rp.erasure.requested');

        await verifiedErasureEndpoint();
      },
      wp116Scenario.timeouts.vitestTestMs
    );

    test(
      '[WP_117]: Wallet Instance sends a valid GET Erasure Request to the attested endpoint',
      async () => {
        assertConformanceOutcome(run.outcome, { expected: 'PASS' });

        const endpoint = await verifiedErasureEndpoint();
        const erasureEvent = requireEvent('rp.erasure.requested');
        expect(erasureEvent.service, 'Erasure Request evidence must be emitted by the Relying Party').toBe(
          'relying-party'
        );
        expect(erasureEvent.diagnostic?.['method'], 'Erasure Request must use HTTP GET').toBe('GET');
        expect(erasureEvent.diagnostic?.['endpoint'], 'Erasure Request must target the erasure endpoint path').toBe(
          new URL(endpoint).pathname
        );
        expect(erasureEvent.diagnostic?.['outcome'], 'Erasure Request must be accepted by the endpoint').toBe(
          'accepted'
        );

        const callbackUrlPresent = erasureEvent.diagnostic?.['callbackUrlPresent'];
        if (callbackUrlPresent !== undefined) {
          expect(callbackUrlPresent, 'Only callback presence may be recorded').toBeTypeOf('boolean');
        }
        expect(erasureEvent.diagnostic, 'Callback URL values must not be exposed in evidence').not.toHaveProperty(
          'callback_url'
        );
        expect(erasureEvent.diagnostic, 'Callback URL values must not be exposed in evidence').not.toHaveProperty(
          'callbackUrl'
        );
      },
      wp116Scenario.timeouts.vitestTestMs
    );
  });

  describe.skipIf(!isSelected(wp085Scenario))('Negative path — Request Object with an unverifiable signature', () => {
    let run: PresentationRun;

    beforeAll(async () => {
      run = await runPresentationScenario(wp085Scenario);
    }, wp085Scenario.timeouts.vitestTestMs);

    test(
      '[WP_085]: Wallet Instance verifies the Request Object signature and presents nothing when it does not verify',
      () => {
        assertConformanceOutcome(run.outcome, { expected: 'PASS' });
        expectFaultApplied(run.events, 'request-object-invalid-signature', { mutatedArtifactPart: 'signature' });
        expectNoPresentation(
          run.events,
          'Wallet must not present a credential for a Request Object whose signature does not verify'
        );
      },
      wp085Scenario.timeouts.vitestTestMs
    );
  });

  describe.skipIf(!isSelected(wp086Scenario))(
    'Negative path — Request Object whose iss does not match the client_id',
    () => {
      let run: PresentationRun;

      beforeAll(async () => {
        run = await runPresentationScenario(wp086Scenario);
      }, wp086Scenario.timeouts.vitestTestMs);

      test(
        '[WP_086]: Wallet Instance checks the Request Object iss against the client_id and the Entity Configuration sub',
        () => {
          assertConformanceOutcome(run.outcome, { expected: 'PASS' });
          expectFaultApplied(run.events, 'request-object-invalid-client-id', { mutatedClaim: 'iss' });
          expectNoPresentation(
            run.events,
            'Wallet must not present a credential for a Request Object with an inconsistent client identifier'
          );
        },
        wp086Scenario.timeouts.vitestTestMs
      );
    }
  );

  describe.skipIf(!isSelected(wp090Scenario))(
    'Negative path — malformed Request Object reported to the response_uri',
    () => {
      let run: PresentationRun;

      beforeAll(async () => {
        run = await runPresentationScenario(wp090Scenario);
      }, wp090Scenario.timeouts.vitestTestMs);

      test(
        '[WP_090]: Wallet Instance sends an Authorization Error Response to the response_uri for a malformed Request Object',
        () => {
          assertConformanceOutcome(run.outcome, { expected: 'PASS' });
          expectFaultApplied(run.events, 'request-object-missing-parameter', { omittedParameter: 'nonce' });

          const errorResponse = findEvent(run.events, 'rp.presentation_error.received');
          expect(
            errorResponse,
            'Wallet must POST an Authorization Error Response to the response_uri when the Request Object is malformed'
          ).toBeDefined();
          expect(errorResponse?.diagnostic?.['method'], 'the error response should be sent via POST').toBe('POST');
          expect(errorResponse?.diagnostic?.['endpoint'], 'the error response should target the response_uri').toBe(
            '/auth/response'
          );
          expect(errorResponse?.diagnostic?.['error'], 'the error response should carry an error code').toBeTypeOf(
            'string'
          );

          expectNoPresentation(run.events, 'Wallet must not present a credential for a malformed Request Object');
        },
        wp090Scenario.timeouts.vitestTestMs
      );
    }
  );

  describe.skipIf(!isSelected(wp091aScenario))(
    'Negative path — response_uri absent from the Relying Party metadata',
    () => {
      let run: PresentationRun;

      beforeAll(async () => {
        run = await runPresentationScenario(wp091aScenario);
      }, wp091aScenario.timeouts.vitestTestMs);

      test(
        '[WP_091a]: Wallet Instance only posts to a response_uri attested in the Relying Party metadata',
        () => {
          assertConformanceOutcome(run.outcome, { expected: 'PASS' });
          expectFaultApplied(run.events, 'unattested-response-uri');

          expect(
            findEvent(run.events, 'rp.presentation_response.received'),
            'Wallet must not post anything to a response_uri that the Relying Party metadata does not attest'
          ).toBeUndefined();
        },
        wp091aScenario.timeouts.vitestTestMs
      );
    }
  );

  describe.skipIf(!isSelected(wp094aScenario))(
    'Negative path — redirect_uri absent from the Relying Party metadata',
    () => {
      let run: PresentationRun;

      beforeAll(async () => {
        run = await runPresentationScenario(wp094aScenario);
      }, wp094aScenario.timeouts.vitestTestMs);

      test(
        '[WP_094a]: Wallet Instance does not follow a redirect_uri that the Relying Party metadata does not attest',
        () => {
          assertConformanceOutcome(run.outcome, { expected: 'PASS' });
          expectFaultApplied(run.events, 'unattested-redirect-uri');

          // The presentation itself must have completed: without it the Relying
          // Party never returns a redirect_uri, so there would be nothing to check.
          const verified = findEvent(run.events, 'vp_token.validation.succeeded');
          expect(
            verified,
            'The presentation must complete before the redirect_uri check can be exercised'
          ).toBeDefined();

          // The Relying Party keeps answering with its live callback endpoint,
          // which the fault removed from the attested redirect_uris — so this is
          // the URI the wallet had to reject. Its path is the one the nominal
          // Entity Configuration attests, so only the fault's replacement of the
          // attested list can make the wallet reject it.
          const returned = new URL(String(verified?.diagnostic?.['redirectUri'] ?? ''));
          expect(
            `${returned.origin}${returned.pathname}`,
            'The Relying Party should return its live callback endpoint as the redirect_uri'
          ).toBe(`${trimTrailingSlash(config['relying-party'].url)}/callback`);

          expect(
            findEvent(run.events, 'rp.redirect.followed'),
            'Wallet must not redirect the user-agent to a redirect_uri the Relying Party does not attest'
          ).toBeUndefined();
        },
        wp094aScenario.timeouts.vitestTestMs
      );
    }
  );

  describe('Relying Party fault cleanup', () => {
    test('deactivated faults leave the Relying Party serving its nominal Entity Configuration', async () => {
      const relyingPartyUrl = config['relying-party'].url;
      const claims = await fetchRelyingPartyEntityConfiguration();
      const verifier = claims.metadata?.openid_credential_verifier as
        { redirect_uris?: string[]; request_uris?: string[]; response_uris?: string[] } | undefined;

      expect(
        claims.authority_hints,
        'The Relying Party must name the configured Trust Anchor again once its faults are deactivated'
      ).toEqual([trimTrailingSlash(config['trust-anchor'].url)]);
      expect(claims.trust_marks, 'The Relying Party must publish its presentation Trust Mark again').not.toEqual([]);
      expect(verifier?.request_uris, 'The Relying Party must attest its live request_uri endpoint again').toEqual([
        `${trimTrailingSlash(relyingPartyUrl)}/auth/request`
      ]);
      expect(verifier?.response_uris, 'The Relying Party must attest its live response_uri endpoint again').toEqual([
        `${trimTrailingSlash(relyingPartyUrl)}/auth/response`
      ]);
      expect(verifier?.redirect_uris, 'The Relying Party must attest its live callback endpoint again').toEqual([
        `${trimTrailingSlash(relyingPartyUrl)}/callback`
      ]);
    }, 15_000);

    test('a later scenario can still activate a fresh Relying Party fault profile', async () => {
      // Each `session.stop()` above already deactivates its own fault, but if any
      // negative scenario had leaked one, this activation (for an unrelated
      // scenario ID) would be rejected with FAULT_ALREADY_ACTIVE by the Relying
      // Party's single-active-fault store.
      const probeScenarioId = `presentation-cleanup-probe-${randomUUID()}`;

      await rpFaultController.activateRpFault({
        scenarioId: probeScenarioId,
        specVersion: '1.3',
        profile: { type: 'invalid-trust-anchor' }
      });

      await rpFaultController.deactivateRpFault({ scenarioId: probeScenarioId });
    }, 10_000);
  });
});
