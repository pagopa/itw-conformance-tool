import { loadConfig } from '@itw-conformance-tool/config';
import { DatabaseClient } from '@itw-conformance-tool/database';
import { afterAll, beforeAll, describe } from 'vitest';

import {
  type ScenarioRunner,
  createProtocolObservedScenarioRunner,
  createSqliteScenarioEventBridge,
  walletInstanceScenarioRegistry
} from '../../index.js';

describe('Test Cases for Wallet Instance', () => {
  let runner: ScenarioRunner;
  let db: DatabaseClient;

  beforeAll(() => {
    const config = loadConfig();
    db = new DatabaseClient(config.global.data_dir);

    const federation = config['trust-anchor'].url;
    const walletProvider = config['wallet-provider'].local_url;
    runner = createProtocolObservedScenarioRunner({
      endpoints: { federation, walletProvider },
      eventBridgeFactory: createSqliteScenarioEventBridge({ db }),
      registry: walletInstanceScenarioRegistry
    });
  });

  afterAll(async () => {
    await runner.close();
    db.close();
  });
});
