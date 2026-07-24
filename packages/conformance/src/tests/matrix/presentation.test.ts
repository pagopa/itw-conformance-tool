import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';

import { loadConfig } from '@itw-conformance-tool/config';
import { DatabaseClient } from '@itw-conformance-tool/database';
import { compactDecrypt, decodeJwt, decodeProtectedHeader, importJWK, type JWK } from 'jose';
import { afterAll, beforeAll, describe, expect, test } from 'vitest';

import {
  assertConformanceOutcome,
  createProtocolObservedScenarioRunner,
  createSqliteScenarioEventBridge,
  presentationScenarioRegistry,
  wpRpHappyScenario
} from '../../index.js';

import type { ObservedEvent, ScenarioOutcome, ScenarioRunner } from '../../index.js';

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
// Authorization Response JWE with the private key whose kid is
// `rp-encryption-key`. WP_092 reads the key from that same file — rather than
// from the SQLite event store — so the test decrypts with the exact key
// material the RP itself uses.
const RP_JWKS_FILE = 'rp/jwks.json';
const RP_ENCRYPTION_KID = 'rp-encryption-key';

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
      (key as JWK).kid === RP_ENCRYPTION_KID &&
      (key as { use?: unknown }).use === 'enc'
  );

  if (!encryptionJwk) {
    throw new Error(`${filePath} must contain an 'enc' JWK with kid ${RP_ENCRYPTION_KID}`);
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

describe('Test Cases for Presentation Phase', () => {
  let runner: ScenarioRunner;
  let db: DatabaseClient;
  let dataDir: string;

  beforeAll(() => {
    const config = loadConfig();
    dataDir = config.global.data_dir;
    db = new DatabaseClient(dataDir);

    const federation = config['trust-anchor'].url;
    const relyingParty = config['relying-party'].url;
    runner = createProtocolObservedScenarioRunner({
      endpoints: { federation, relyingParty },
      eventBridgeFactory: createSqliteScenarioEventBridge({ db }),
      registry: presentationScenarioRegistry
    });
  });

  afterAll(async () => {
    await runner.close();
    db.close();
  });

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
  describe('Happy path — full remote presentation flow', () => {
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
      expect(header.kid, 'JWE should target the RP encryption key').toBe(RP_ENCRYPTION_KID);

      // Decrypt with the RP's own encryption private key, loaded from the same
      // `rp/jwks.json` the RP reads at startup and imported the same way the RP
      // imports it (ECDH-ES). A successful decryption proves the wallet encrypted
      // the Authorization Response to the Relying Party's advertised key.
      const encryptionJwk = await loadRpEncryptionPrivateJwk(dataDir);
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
        '/callback/:state'
      );
    });
  });
});
