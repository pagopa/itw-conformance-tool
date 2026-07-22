import { loadConfig, type ConfigSchemaType } from '@itw-conformance-tool/config';
import { DatabaseClient } from '@itw-conformance-tool/database';
import { parsePushedAuthorizationRequest } from '@pagopa/io-wallet-oauth2';
import { IoWalletSdkConfig, ItWalletSpecsVersion, type HttpMethod } from '@pagopa/io-wallet-utils';
import { afterAll, beforeAll, describe, expect, test } from 'vitest';

import {
  assertConformanceOutcome,
  createProtocolObservedScenarioRunner,
  createSqliteScenarioEventBridge,
  issuanceScenarioRegistry,
  wpCiHappyScenario
} from '../../index.js';

import type { ObservedEvent, ScenarioOutcome, ScenarioRunner } from '../../index.js';

function toHeaders(value: unknown): Headers {
  if (value === null || typeof value !== 'object') {
    throw new Error('issuer.par.requested evidence is missing header data');
  }

  const entries = Object.entries(value as Record<string, unknown>).filter(
    (entry): entry is [string, string] => typeof entry[1] === 'string'
  );

  return new Headers(entries);
}

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

    beforeAll(async () => {
      const session = await runner.start(wpCiHappyScenario.id);
      try {
        await session.showInstructions();
        outcome = await session.awaitVerdict();
        events = session.events.all();
      } finally {
        await session.stop();
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
      async () => {
        assertConformanceOutcome(outcome, { expected: 'PASS' });

        const parEvent = events.find((event) => event.name === 'issuer.par.requested');
        expect(parEvent).toBeDefined();

        const body = parEvent?.diagnostic?.['body'];
        const headers = parEvent?.diagnostic?.['headers'];
        const endpoint = parEvent?.diagnostic?.['endpoint'];

        const { authorizationRequest } = await parsePushedAuthorizationRequest({
          authorizationRequest: body,
          callbacks: { fetch: globalThis.fetch },
          config: new IoWalletSdkConfig({
            itWalletSpecsVersion: ItWalletSpecsVersion.V1_4
          }),
          request: {
            headers: toHeaders(headers),
            method: 'POST' as HttpMethod,
            url: `${config['credential-issuer'].url}${endpoint}`
          }
        });

        expect(authorizationRequest.client_id).not.toHaveLength(0);
        expect(authorizationRequest.response_type).toBe('code');
      },
      wpCiHappyScenario.timeouts.vitestTestMs
    );
  });
});
