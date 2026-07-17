import { loadConfig } from '@itw-conformance-tool/config';
import { DatabaseClient } from '@itw-conformance-tool/database';
import { afterAll, beforeAll, describe } from 'vitest';

import {
  createProtocolObservedScenarioRunner,
  createSqliteScenarioEventBridge,
  issuanceScenarioRegistry
} from '../../index.js';

import type { ScenarioRunner } from '../../index.js';

describe('Test Cases for Issuance Phase', () => {
  let runner: ScenarioRunner;
  let db: DatabaseClient;

  beforeAll(() => {
    const config = loadConfig();
    db = new DatabaseClient(config.global.data_dir);

    const credentialIssuer = config['credential-issuer'].url;
    runner = createProtocolObservedScenarioRunner({
      endpoints: { credentialIssuer },
      eventBridgeFactory: createSqliteScenarioEventBridge({ db }),
      registry: issuanceScenarioRegistry
    });
  });

  afterAll(async () => {
    await runner.close();
    db.close();
  });
});
