import { loadConfig } from '@itw-conformance-tool/config';
import { DatabaseClient } from '@itw-conformance-tool/database';
import { afterAll, beforeAll, describe, test } from 'vitest';

import {
  assertConformanceOutcome,
  createProtocolObservedScenarioRunner,
  createSqliteScenarioEventBridge,
  presentationScenarioRegistry,
  wp077Scenario,
  wp080Scenario
} from '../../index.js';

import type { ScenarioRunner } from '../../index.js';

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
});
