import { join, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import { afterAll, beforeAll, describe, it } from 'vitest';

import {
  assertConformanceOutcome,
  createProtocolObservedScenarioRunner,
  createSqliteScenarioEventBridge,
  issuanceScenarioRegistry,
  wp046Scenario
} from '../../index.js';

import type { ScenarioRunner } from '../../index.js';

function readBooleanEnv(name: string, defaultValue: boolean): boolean {
  const value = process.env[name]?.trim().toLowerCase();
  if (!value) return defaultValue;
  return value === 'true' || value === '1';
}

function readPositivePort(value: string | undefined, defaultPort: number): number {
  if (!value?.trim()) return defaultPort;
  const port = Number(value);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) throw new Error(`Invalid port: ${value}`);
  return port;
}

function resolveDataDir(): string {
  return process.env.ITW_CT_DATA_DIR?.trim() || resolve(process.cwd(), '.itw-conformance-tool');
}

function resolveCredentialIssuerEndpoint(): string {
  const explicitBaseUrl = process.env.ITW_CT_ISSUER_ADVERTISED_BASE_URL?.trim();
  if (explicitBaseUrl) return explicitBaseUrl.replace(/\/$/, '');

  const httpsEnabled = readBooleanEnv('ITW_CT_HTTPS', true);
  const scheme = httpsEnabled ? 'https' : 'http';
  const host = process.env.ITW_CT_ADVERTISED_HOST?.trim() || '127.0.0.1';
  const port = readPositivePort(process.env.ITW_CT_ISSUER_PORT, 3000);

  return `${scheme}://${host}:${port}`;
}

describe.sequential('Issuance protocol-observed tests', () => {
  let runner: ScenarioRunner;
  let db: DatabaseSync;

  beforeAll(() => {
    db = new DatabaseSync(join(resolveDataDir(), 'itw.db'));
    db.exec('PRAGMA busy_timeout = 5000;');

    runner = createProtocolObservedScenarioRunner({
      endpoints: { credentialIssuer: resolveCredentialIssuerEndpoint() },
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
