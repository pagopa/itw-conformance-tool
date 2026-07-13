import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { loadConfig } from '@itw-conformance-tool/config';
import { afterAll, beforeAll, describe, it } from 'vitest';

import {
  assertConformanceOutcome,
  createProtocolObservedScenarioRunner,
  createSqliteScenarioEventBridge,
  issuanceScenarioRegistry,
  wp046Scenario
} from '../../index.js';

import type { ScenarioRunner } from '../../index.js';

describe.sequential('Issuance protocol-observed tests', () => {
  let runner: ScenarioRunner;
  let db: DatabaseSync;
  let issuerBaseUrl: string;

  beforeAll(() => {
    const config = loadConfig();
    db = new DatabaseSync(join(config.global.data_dir, 'itw.db'));
    db.exec('PRAGMA busy_timeout = 5000;');
    issuerBaseUrl = `https://127.0.0.1:${config['itw-credential-issuer'].port}`;

    runner = createProtocolObservedScenarioRunner({
      endpoints: { credentialIssuer: issuerBaseUrl },
      eventBridgeFactory: createSqliteScenarioEventBridge({ db }),
      registry: issuanceScenarioRegistry
    });
  });

  afterAll(async () => {
    await runner.close();
    db.close();
  });

  it(
    `[ISSUANCE:FEDERATION] ${wp046Scenario.id}: ${wp046Scenario.title}`,
    async () => {
      const session = await runner.start(wp046Scenario.id);

      try {
        await session.showInstructions();
        const outcome = await session.awaitVerdict();
        assertConformanceOutcome(outcome, { expected: 'PASS' });
      } finally {
        await session.stop();
      }
    },
    wp046Scenario.timeouts.vitestTestMs
  );
});
