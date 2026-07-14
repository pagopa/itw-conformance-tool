import { loadConfig } from '@itw-conformance-tool/config';
import { DatabaseClient } from '@itw-conformance-tool/database';
import { afterAll, beforeAll, describe } from 'vitest';

import {
  createProtocolObservedScenarioRunner,
  createSqliteScenarioEventBridge,
  walletInstanceScenarioRegistry
} from '../../index.js';

import type { ScenarioRunner } from '../../index.js';

describe.sequential('Test Cases for Issuance Phase', () => {
  let runner: ScenarioRunner;
  let db: DatabaseClient;

  beforeAll(() => {
    const config = loadConfig();
    db = new DatabaseClient(config.global.data_dir);

    const credentialIssuer = config['credential-issuer'].url;
    const relyingParty = config['relying-party'].url;
    runner = createProtocolObservedScenarioRunner({
      endpoints: { credentialIssuer, relyingParty },
      eventBridgeFactory: createSqliteScenarioEventBridge({ db }),
      registry: walletInstanceScenarioRegistry
    });
  });

  afterAll(async () => {
    await runner.close();
    db.close();
  });
});
