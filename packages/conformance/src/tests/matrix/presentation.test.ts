import { loadConfig } from '@itw-conformance-tool/config';
import { DatabaseClient } from '@itw-conformance-tool/database';
import { afterAll, beforeAll, describe, test } from 'vitest';

import {
  assertConformanceOutcome,
  createProtocolObservedScenarioRunner,
  createSqliteScenarioEventBridge,
  presentationScenarioRegistry,
  wp077Scenario,
  wp080Scenario,
  wpRpHappyScenario
} from '../../index.js';

import type { ScenarioOutcome, ScenarioRunner } from '../../index.js';

describe('Test Cases for Presentation Phase', () => {
  let runner: ScenarioRunner;
  let db: DatabaseClient;

  beforeAll(() => {
    const config = loadConfig();
    db = new DatabaseClient(config.global.data_dir);

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

  test(
    `[${wp077Scenario.id}]: ${wp077Scenario.title}`,
    async () => {
      const session = await runner.start(wp077Scenario.id);

      try {
        await session.showInstructions();
        const outcome = await session.awaitVerdict();
        assertConformanceOutcome(outcome, { expected: 'PASS' });
      } finally {
        await session.stop();
      }
    },
    wp077Scenario.timeouts.vitestTestMs
  );

  test(
    `[${wp080Scenario.id}]: ${wp080Scenario.title}`,
    async () => {
      const session = await runner.start(wp080Scenario.id);

      try {
        await session.showInstructions();
        const outcome = await session.awaitVerdict();
        assertConformanceOutcome(outcome, { expected: 'PASS' });
      } finally {
        await session.stop();
      }
    },
    wp080Scenario.timeouts.vitestTestMs
  );

  // A single happy-path remote presentation run exercises every
  // RP/Trust-Anchor-observable endpoint call, so one flow satisfies many Wallet
  // Solution Test Matrix cases at once. Each row below is a matrix case whose
  // expected effect is covered by that run.
  //
  // Only the happy-path, protocol-observable cases are linked here. Conflicting
  // cases are resolved by choosing one variant: WP_076 (deep-link / same-device)
  // over WP_077 (QR / cross-device) so the WP_094 redirect is observable, and
  // WP_082 (GET) over WP_083 (POST) — the RP advertises no request_uri_method,
  // so the wallet fetches the Request Object over GET. The negative cases
  // (WP_081, WP_085, WP_086, WP_087, WP_090, WP_091a, WP_094a) and the UI-only
  // cases (WP_088, WP_089, WP_089a, WP_089b) require dedicated unhappy-path
  // scenarios and are intentionally excluded.
  describe('Happy path — full remote presentation flow', () => {
    let outcome: ScenarioOutcome;

    beforeAll(async () => {
      const session = await runner.start(wpRpHappyScenario.id);

      try {
        await session.showInstructions();
        outcome = await session.awaitVerdict();
      } finally {
        await session.stop();
      }
    }, wpRpHappyScenario.timeouts.vitestTestMs);

    const matrixCases: [id: string, description: string][] = [
      ['WP_076', 'Wallet Instance obtains the Remote Presentation URL from a deep link'],
      ['WP_078', 'Wallet Instance fetches the Relying Party OpenID Federation endpoint'],
      ['WP_079', 'Wallet Instance resolves the Relying Party OpenID Federation Trust Chain'],
      ['WP_080', 'Wallet Instance invokes the endpoints required to evaluate the Relying Party Trust Marks'],
      ['WP_082', 'Wallet Instance retrieves the Request Object via HTTP GET to the request_uri endpoint'],
      ['WP_084', 'Wallet Instance retrieves the Relying Party keys from metadata.openid_credential_verifier.jwks'],
      ['WP_091', 'Wallet Instance sends the Authorization Response via HTTP POST to the response_uri endpoint'],
      ['WP_092', 'Wallet Instance encrypts the Authorization Response with the Relying Party key'],
      [
        'WP_093',
        'Wallet Instance builds the vp_token with the Request Object state and one entry per requested credential'
      ],
      ['WP_093a', 'Wallet Instance includes at least one SD-JWT disclosure in the vp_token'],
      ['WP_093b', 'Wallet Instance appends a Key Binding JWT to every SD-JWT presentation'],
      ['WP_093c', 'Wallet Instance uses the required Key Binding JWT header and payload format'],
      ['WP_094', 'Wallet Instance follows the redirect_uri returned by the Relying Party']
    ];

    test.each(matrixCases)('[%s]: %s', () => {
      assertConformanceOutcome(outcome, { expected: 'PASS' });
    });
  });
});
